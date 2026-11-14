//! STML server (Rust/axum + PostgreSQL), P1 read/write core.
//!
//! Implemented: enrolment, signed heartbeat/inventory/reports, agents query.
//! Not yet: operator auth, policies/approvals, trust/learning parity.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, types::Json as SqlJson, PgPool, Row};
use uuid::Uuid;

type ApiError = (StatusCode, Json<Value>);

#[derive(Clone)]
struct AppState {
    pool: Option<PgPool>,
    admin_token: String,
    viewer_token: String,
    approver_token: String,
    policy_pubkey: String,
    require_approval: bool,
    trust_dir: String,
}

fn err(code: StatusCode, message: impl Into<String>) -> ApiError {
    (code, Json(json!({"error": message.into()})))
}

fn pool(state: &AppState) -> Result<&PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "database not configured"))
}

fn parse_uuid(value: &Value, key: &str) -> Result<Uuid, ApiError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, format!("{key} must be uuid")))
}

fn parse_public_key(pem_text: &str) -> Result<VerifyingKey, ApiError> {
    let pem = pem::parse(pem_text)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("bad pubkey PEM: {e}")))?;
    let spki = spki::SubjectPublicKeyInfoRef::try_from(pem.contents())
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("bad SPKI: {e}")))?;
    let raw = spki.subject_public_key.raw_bytes();
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "pubkey must be Ed25519"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("bad key: {e}")))
}

fn verify_body(headers: &HeaderMap, body: &[u8], pem_text: &str) -> Result<(), ApiError> {
    let encoded = headers
        .get("x-stml-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "X-STML-Signature required"))?;
    let raw = STANDARD
        .decode(encoded)
        .map_err(|_| err(StatusCode::FORBIDDEN, "bad signature encoding"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| err(StatusCode::FORBIDDEN, "bad signature length"))?;
    let key = parse_public_key(pem_text)?;
    key.verify_strict(body, &signature)
        .map_err(|_| err(StatusCode::FORBIDDEN, "bad signature"))
}

fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}

fn auth(headers: &HeaderMap, state: &AppState, role: &str) -> Result<(), ApiError> {
    if state.admin_token.is_empty() {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "operator auth not configured",
        ));
    }
    let token = bearer(headers);
    match role {
        "admin" if token == state.admin_token => Ok(()),
        "approver" if token == state.approver_token => Ok(()),
        "viewer"
            if token == state.admin_token
                || token == state.viewer_token
                || token == state.approver_token =>
        {
            Ok(())
        }
        _ => Err(err(StatusCode::FORBIDDEN, format!("{role} required"))),
    }
}

fn canonical_policy(value: &Value) -> Result<Vec<u8>, ApiError> {
    let body = json!({
        "policy_id": value.get("policy_id").and_then(Value::as_str).unwrap_or(""),
        "version": value.get("version").and_then(Value::as_str).unwrap_or(""),
        "channel": value.get("channel").and_then(Value::as_str).unwrap_or("stable"),
        "content": value.get("content").cloned().unwrap_or_else(|| json!({})),
    });
    serde_json::to_vec(&body).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))
}

fn key_id_of(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.to_bytes());
    let hex = format!("{digest:x}");
    hex[..16].to_string()
}

fn verify_policy(state: &AppState, value: &Value) -> Result<(), ApiError> {
    if state.policy_pubkey.is_empty() {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "policy pubkey not configured",
        ));
    }
    let key = parse_public_key(&state.policy_pubkey)?;
    if value.get("key_id").and_then(Value::as_str).unwrap_or("") != key_id_of(&key) {
        return Err(err(StatusCode::FORBIDDEN, "policy key_id mismatch"));
    }
    let signature = STANDARD
        .decode(value.get("signature").and_then(Value::as_str).unwrap_or(""))
        .map_err(|_| err(StatusCode::FORBIDDEN, "bad policy signature encoding"))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| err(StatusCode::FORBIDDEN, "bad policy signature length"))?;
    key.verify_strict(&canonical_policy(value)?, &signature)
        .map_err(|_| err(StatusCode::FORBIDDEN, "bad policy signature"))
}

async fn list_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "viewer")?;
    let db = pool(&state)?;
    let rows = sqlx::query(
        "SELECT policy_id, version, channel, key_id, created_at::text AS created_at \
         FROM policies ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "policy_id": r.get::<String, _>("policy_id"),
                "version": r.get::<String, _>("version"),
                "channel": r.get::<String, _>("channel"),
                "key_id": r.get::<String, _>("key_id"),
                "created_at": r.get::<String, _>("created_at"),
            })
        })
        .collect();
    Ok(Json(json!({"policies": out})))
}

async fn add_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("json: {e}")))?;
    verify_policy(&state, &value)?;
    let db = pool(&state)?;
    let tenant = value
        .get("tenant_id")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let policy_id = value.get("policy_id").and_then(Value::as_str).unwrap_or("");
    let version = value.get("version").and_then(Value::as_str).unwrap_or("");
    let channel = value
        .get("channel")
        .and_then(Value::as_str)
        .unwrap_or("stable");
    let content = value.get("content").cloned().unwrap_or_else(|| json!({}));
    let key_id = value.get("key_id").and_then(Value::as_str).unwrap_or("");
    let signature = value.get("signature").and_then(Value::as_str).unwrap_or("");
    let inserted = sqlx::query(
        "INSERT INTO policies(tenant_id, policy_id, version, channel, content, key_id, \
         signature, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,now()) \
         ON CONFLICT (tenant_id, policy_id, version) DO NOTHING",
    )
    .bind(tenant)
    .bind(policy_id)
    .bind(version)
    .bind(channel)
    .bind(SqlJson(content))
    .bind(key_id)
    .bind(signature)
    .execute(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if inserted.rows_affected() == 0 {
        return Err(err(StatusCode::CONFLICT, "policy version already exists"));
    }
    let approval_id: i64 = sqlx::query_scalar(
        "INSERT INTO approvals(tenant_id, kind, target, payload, proposed_by, status, created_at) \
         VALUES ($1,'policy',$2,$3,'operator','pending',now()) RETURNING id",
    )
    .bind(tenant)
    .bind(format!("{policy_id}@{version}"))
    .bind(SqlJson(value.clone()))
    .fetch_one(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(
        json!({"ok": true, "policy_id": policy_id, "version": version,
                   "approval_id": approval_id}),
    ))
}

async fn list_approvals(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "viewer")?;
    let db = pool(&state)?;
    let rows = sqlx::query(
        "SELECT id, kind, target, status, proposed_by, decided_by FROM approvals \
         ORDER BY id DESC",
    )
    .fetch_all(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>("id"),
                "kind": r.get::<String, _>("kind"),
                "target": r.get::<String, _>("target"),
                "status": r.get::<String, _>("status"),
                "proposed_by": r.get::<String, _>("proposed_by"),
                "decided_by": r.get::<Option<String>, _>("decided_by"),
            })
        })
        .collect();
    Ok(Json(json!({"approvals": out})))
}

async fn decide_approval(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path((approval_id, action)): axum::extract::Path<(i64, String)>,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "approver")?;
    let status = match action.as_str() {
        "approve" => "approved",
        "deny" => "rejected",
        _ => return Err(err(StatusCode::NOT_FOUND, "unknown action")),
    };
    let db = pool(&state)?;
    let changed = sqlx::query(
        "UPDATE approvals SET status = $1, decided_by = 'approver', decided_at = now() \
         WHERE id = $2 AND status = 'pending'",
    )
    .bind(status)
    .bind(approval_id)
    .execute(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if changed.rows_affected() == 0 {
        return Err(err(
            StatusCode::NOT_FOUND,
            "unknown or already decided approval",
        ));
    }
    Ok(Json(
        json!({"ok": true, "approval_id": approval_id, "status": status}),
    ))
}

async fn start_rollout(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("json: {e}")))?;
    let policy_id = value.get("policy_id").and_then(Value::as_str).unwrap_or("");
    let version = value.get("version").and_then(Value::as_str).unwrap_or("");
    let percent = value
        .get("percent")
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .clamp(1, 100);
    let tenant = value
        .get("tenant_id")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let db = pool(&state)?;
    if state.require_approval {
        let approved = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM approvals WHERE kind='policy' AND target=$1 \
             AND status='approved' AND tenant_id=$2",
        )
        .bind(format!("{policy_id}@{version}"))
        .bind(tenant)
        .fetch_one(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if approved == 0 {
            return Err(err(StatusCode::CONFLICT, "policy approval required"));
        }
    }
    let policy =
        sqlx::query("SELECT 1 FROM policies WHERE tenant_id=$1 AND policy_id=$2 AND version=$3")
            .bind(tenant)
            .bind(policy_id)
            .bind(version)
            .fetch_optional(db)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if policy.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "unknown policy"));
    }
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM agents WHERE tenant_id=$1")
        .bind(tenant)
        .fetch_one(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let target = if percent == 0 {
        0
    } else {
        ((count * percent + 99) / 100).max(1)
    };
    let agents = sqlx::query(
        "SELECT id, policy_version FROM agents WHERE tenant_id=$1 ORDER BY hostname LIMIT $2",
    )
    .bind(tenant)
    .bind(target)
    .fetch_all(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let status = if percent >= 100 {
        "completed"
    } else {
        "running"
    };
    let rollout_id: i64 = sqlx::query_scalar(
        "INSERT INTO rollouts(tenant_id, policy_id, version, percent, status, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,now(),now()) RETURNING id",
    )
    .bind(tenant)
    .bind(policy_id)
    .bind(version)
    .bind(percent)
    .bind(status)
    .fetch_one(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    for row in &agents {
        let agent_id: Uuid = row.get("id");
        let old: Option<String> = row.get("policy_version");
        sqlx::query(
            "INSERT INTO rollout_agents(rollout_id, agent_id, old_version) \
                     VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
        )
        .bind(rollout_id)
        .bind(agent_id)
        .bind(old)
        .execute(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        sqlx::query("UPDATE agents SET policy_version=$1 WHERE id=$2")
            .bind(version)
            .bind(agent_id)
            .execute(db)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    Ok(Json(
        json!({"rollout_id": rollout_id, "percent": percent, "status": status,
                   "applied": agents.len()}),
    ))
}

async fn promote_rollout(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(rollout_id): axum::extract::Path<i64>,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let db = pool(&state)?;
    let row = sqlx::query("SELECT tenant_id, version, percent, status FROM rollouts WHERE id=$1")
        .bind(rollout_id)
        .fetch_optional(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown rollout"))?;
    let status: String = row.get("status");
    if status != "running" {
        return Err(err(StatusCode::CONFLICT, "rollout is not running"));
    }
    let current: i32 = row.get("percent");
    let next = [1, 10, 50, 100]
        .into_iter()
        .find(|s| *s > current)
        .unwrap_or(100);
    let tenant: String = row.get("tenant_id");
    let version: String = row.get("version");
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM agents WHERE tenant_id=$1")
        .bind(&tenant)
        .fetch_one(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let target = ((count * next as i64 + 99) / 100).max(1);
    let agents = sqlx::query(
        "SELECT id, policy_version FROM agents WHERE tenant_id=$1 ORDER BY hostname LIMIT $2",
    )
    .bind(&tenant)
    .bind(target)
    .fetch_all(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut applied = 0;
    for row in &agents {
        let agent_id: Uuid = row.get("id");
        let old: Option<String> = row.get("policy_version");
        let res = sqlx::query(
            "INSERT INTO rollout_agents(rollout_id, agent_id, old_version) \
             VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
        )
        .bind(rollout_id)
        .bind(agent_id)
        .bind(old)
        .execute(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if res.rows_affected() > 0 {
            applied += 1;
        }
        sqlx::query("UPDATE agents SET policy_version=$1 WHERE id=$2")
            .bind(&version)
            .bind(agent_id)
            .execute(db)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    let status = if next >= 100 { "completed" } else { "running" };
    sqlx::query("UPDATE rollouts SET percent=$1, status=$2, updated_at=now() WHERE id=$3")
        .bind(next)
        .bind(status)
        .bind(rollout_id)
        .execute(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(
        json!({"rollout_id": rollout_id, "percent": next, "status": status,
                   "applied": applied}),
    ))
}

async fn rollout_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path((rollout_id, action)): axum::extract::Path<(i64, String)>,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let db = pool(&state)?;
    if action == "promote" {
        return promote_rollout(State(state), headers, axum::extract::Path(rollout_id)).await;
    }
    match action.as_str() {
        "halt" => {
            let changed = sqlx::query(
                "UPDATE rollouts SET status='halted', updated_at=now() WHERE id=$1 AND status='running'",
            )
            .bind(rollout_id)
            .execute(db)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            if changed.rows_affected() == 0 {
                return Err(err(StatusCode::NOT_FOUND, "unknown or finished rollout"));
            }
        }
        "rollback" => {
            let rows =
                sqlx::query("SELECT agent_id, old_version FROM rollout_agents WHERE rollout_id=$1")
                    .bind(rollout_id)
                    .fetch_all(db)
                    .await
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            if rows.is_empty() {
                return Err(err(StatusCode::NOT_FOUND, "unknown rollout"));
            }
            for row in rows {
                let agent_id: Uuid = row.get("agent_id");
                let old: Option<String> = row.get("old_version");
                sqlx::query("UPDATE agents SET policy_version=$1 WHERE id=$2")
                    .bind(old)
                    .bind(agent_id)
                    .execute(db)
                    .await
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            }
            sqlx::query("UPDATE rollouts SET status='rolled_back', updated_at=now() WHERE id=$1")
                .bind(rollout_id)
                .execute(db)
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        _ => return Err(err(StatusCode::NOT_FOUND, "unknown action")),
    }
    Ok(Json(
        json!({"ok": true, "rollout_id": rollout_id, "action": action}),
    ))
}

async fn get_rollout(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(rollout_id): axum::extract::Path<i64>,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "viewer")?;
    let db = pool(&state)?;
    let row = sqlx::query(
        "SELECT id, tenant_id, policy_id, version, percent, status, created_at::text AS created_at \
         FROM rollouts WHERE id=$1",
    )
    .bind(rollout_id)
    .fetch_optional(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(row) = row else {
        return Err(err(StatusCode::NOT_FOUND, "unknown rollout"));
    };
    let agents = sqlx::query(
        "SELECT agent_id::text AS agent_id, old_version FROM rollout_agents WHERE rollout_id=$1",
    )
    .bind(rollout_id)
    .fetch_all(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let applied: Vec<Value> = agents
        .into_iter()
        .map(|r| {
            json!({"agent_id": r.get::<String, _>("agent_id"),
                        "old_version": r.get::<Option<String>, _>("old_version")})
        })
        .collect();
    Ok(Json(json!({
        "id": row.get::<i64, _>("id"),
        "tenant_id": row.get::<String, _>("tenant_id"),
        "policy_id": row.get::<String, _>("policy_id"),
        "version": row.get::<String, _>("version"),
        "percent": row.get::<i32, _>("percent"),
        "status": row.get::<String, _>("status"),
        "created_at": row.get::<String, _>("created_at"),
        "agents": applied,
    })))
}

fn normalize_serial(serial: &str) -> String {
    serial.replace(':', "").replace(' ', "").to_uppercase()
}

async fn add_audit(
    db: &PgPool,
    actor: &str,
    action: &str,
    target: &str,
) -> Result<(), sqlx::Error> {
    let prev: Option<String> =
        sqlx::query_scalar("SELECT hash FROM audit ORDER BY id DESC LIMIT 1")
            .fetch_optional(db)
            .await?;
    let prev = prev.unwrap_or_else(|| "0".repeat(64));
    let ts = Utc::now().timestamp_micros();
    let body = format!("{ts}|{actor}|{action}|{target}|{prev}");
    let hash = hex::encode(Sha256::digest(body.as_bytes()));
    sqlx::query(
        "INSERT INTO audit(ts_micros, actor, action, target, prev_hash, hash) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(ts)
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(&prev)
    .bind(&hash)
    .execute(db)
    .await?;
    Ok(())
}

async fn create_key_value(
    state: &AppState,
    db: &PgPool,
    key_class: &str,
    rotated_from: Option<&str>,
) -> Result<Value, ApiError> {
    if !["root", "policy", "model", "driver", "connector"].contains(&key_class) {
        return Err(err(StatusCode::BAD_REQUEST, "unknown key class"));
    }
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    let key_id = key_id_of(&verifying);
    let dir = std::path::Path::new(&state.trust_dir);
    std::fs::create_dir_all(dir)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let private_path = dir.join(format!("{key_id}.hex"));
    std::fs::write(&private_path, hex::encode(signing.to_bytes()))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    sqlx::query(
        "INSERT INTO keys(key_id, key_class, public_hex, private_path, created_at, rotated_from) \
         VALUES ($1,$2,$3,$4,now(),$5)",
    )
    .bind(&key_id)
    .bind(key_class)
    .bind(hex::encode(verifying.to_bytes()))
    .bind(private_path.to_string_lossy().to_string())
    .bind(rotated_from)
    .execute(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    add_audit(db, "trust", "key_create", &format!("{key_class}:{key_id}"))
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(json!({"key_id": key_id, "key_class": key_class,
              "public_hex": hex::encode(verifying.to_bytes())}))
}

async fn create_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("json: {e}")))?;
    let db = pool(&state)?;
    let class = value
        .get("key_class")
        .and_then(Value::as_str)
        .unwrap_or("policy");
    Ok(Json(create_key_value(&state, db, class, None).await?))
}

async fn list_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "viewer")?;
    let db = pool(&state)?;
    let rows = sqlx::query(
        "SELECT key_id, key_class, public_hex, created_at::text AS created_at, \
         revoked_at::text AS revoked_at, rotated_from FROM keys ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "key_id": r.get::<String, _>("key_id"),
                "key_class": r.get::<String, _>("key_class"),
                "public_hex": r.get::<String, _>("public_hex"),
                "created_at": r.get::<String, _>("created_at"),
                "revoked_at": r.get::<Option<String>, _>("revoked_at"),
                "rotated_from": r.get::<Option<String>, _>("rotated_from"),
            })
        })
        .collect();
    Ok(Json(json!({"keys": out})))
}

async fn key_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path((key_id, action)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let db = pool(&state)?;
    match action.as_str() {
        "revoke" => {
            let changed = sqlx::query(
                "UPDATE keys SET revoked_at=now() WHERE key_id=$1 AND revoked_at IS NULL",
            )
            .bind(&key_id)
            .execute(db)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            if changed.rows_affected() == 0 {
                return Err(err(StatusCode::NOT_FOUND, "unknown or revoked key"));
            }
            add_audit(db, "trust", "key_revoke", &key_id)
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok(Json(json!({"ok": true, "key_id": key_id, "revoked": true})))
        }
        "rotate" => {
            let class: Option<String> =
                sqlx::query_scalar("SELECT key_class FROM keys WHERE key_id=$1")
                    .bind(&key_id)
                    .fetch_optional(db)
                    .await
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let Some(class) = class else {
                return Err(err(StatusCode::NOT_FOUND, "unknown key"));
            };
            Ok(Json(
                create_key_value(&state, db, &class, Some(&key_id)).await?,
            ))
        }
        _ => Err(err(StatusCode::NOT_FOUND, "unknown action")),
    }
}

async fn revoke_cert(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("json: {e}")))?;
    let serial = normalize_serial(value.get("serial").and_then(Value::as_str).unwrap_or(""));
    if serial.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "serial required"));
    }
    let db = pool(&state)?;
    sqlx::query(
        "INSERT INTO revoked_certs(serial, revoked_at, reason) VALUES ($1, now(), $2) \
         ON CONFLICT (serial) DO UPDATE SET revoked_at=now()",
    )
    .bind(&serial)
    .bind(
        value
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("operator"),
    )
    .execute(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    add_audit(db, "operator", "cert_revoke", &serial)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"ok": true, "serial": serial})))
}

async fn list_revoked(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let db = pool(&state)?;
    let rows = sqlx::query(
        "SELECT serial, revoked_at::text AS revoked_at, reason FROM revoked_certs \
         ORDER BY revoked_at DESC",
    )
    .fetch_all(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({"serial": r.get::<String, _>("serial"),
                        "revoked_at": r.get::<String, _>("revoked_at"),
                        "reason": r.get::<Option<String>, _>("reason")})
        })
        .collect();
    Ok(Json(json!({"revoked": out})))
}

async fn verify_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let db = pool(&state)?;
    let rows = sqlx::query(
        "SELECT ts_micros, actor, action, target, prev_hash, hash FROM audit ORDER BY id",
    )
    .fetch_all(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut prev = "0".repeat(64);
    for row in rows {
        let ts: i64 = row.get("ts_micros");
        let actor: String = row.get("actor");
        let action: String = row.get("action");
        let target: String = row.get("target");
        let prev_hash: String = row.get("prev_hash");
        let hash: String = row.get("hash");
        let body = format!("{ts}|{actor}|{action}|{target}|{prev_hash}");
        if prev_hash != prev || hex::encode(Sha256::digest(body.as_bytes())) != hash {
            return Ok(Json(json!({"ok": false})));
        }
        prev = hash;
    }
    Ok(Json(json!({"ok": true})))
}

fn sanitize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if ["raw", "cmdline", "path", "username", "email"].contains(&k.as_str()) {
                    continue;
                }
                out.insert(k.clone(), sanitize(v));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sanitize).collect()),
        other => other.clone(),
    }
}

async fn telemetry(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("json: {e}")))?;
    if !value
        .get("consent")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(err(StatusCode::FORBIDDEN, "telemetry consent required"));
    }
    let events = value
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "events[] required"))?;
    if events.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "events[] empty"));
    }
    let db = pool(&state)?;
    let tenant = value
        .get("tenant_id")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let agent_id = value
        .get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    sqlx::query(
        "INSERT INTO telemetry(tenant_id, agent_id, consent, events, created_at) \
         VALUES ($1,$2,true,$3,now())",
    )
    .bind(tenant)
    .bind(agent_id)
    .bind(SqlJson(sanitize(&Value::Array(events.clone()))))
    .execute(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    add_audit(db, "learning", "telemetry_ingest", agent_id)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"ok": true, "accepted": events.len()})))
}

async fn add_case(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("json: {e}")))?;
    let case_id = value.get("case_id").and_then(Value::as_str).unwrap_or("");
    let label = value.get("label").and_then(Value::as_str).unwrap_or("");
    if case_id.is_empty() || !["TP", "FP"].contains(&label) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "case_id and label TP|FP required",
        ));
    }
    let db = pool(&state)?;
    sqlx::query(
        "INSERT INTO cases(case_id, tenant_id, report_id, label, holdout, features, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,now()) ON CONFLICT (case_id) DO NOTHING",
    )
    .bind(case_id)
    .bind(
        value
            .get("tenant_id")
            .and_then(Value::as_str)
            .unwrap_or("default"),
    )
    .bind(value.get("report_id").and_then(Value::as_str))
    .bind(label)
    .bind(
        value
            .get("holdout")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
    .bind(SqlJson(
        value.get("features").cloned().unwrap_or_else(|| json!({})),
    ))
    .execute(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    add_audit(db, "learning", "case_add", case_id)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"ok": true, "case_id": case_id})))
}

async fn list_cases(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "viewer")?;
    let db = pool(&state)?;
    let rows = sqlx::query(
        "SELECT case_id, report_id, label, holdout, created_at::text AS created_at \
         FROM cases ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({"case_id": r.get::<String, _>("case_id"),
                        "report_id": r.get::<Option<String>, _>("report_id"),
                        "label": r.get::<String, _>("label"),
                        "holdout": r.get::<bool, _>("holdout"),
                        "created_at": r.get::<String, _>("created_at")})
        })
        .collect();
    Ok(Json(json!({"cases": out})))
}

async fn add_model(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("json: {e}")))?;
    let name = value.get("name").and_then(Value::as_str).unwrap_or("");
    let version = value.get("version").and_then(Value::as_str).unwrap_or("");
    if name.is_empty() || version.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "name and version required"));
    }
    let db = pool(&state)?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO models(tenant_id, name, version, metrics, signature, status, created_at) \
         VALUES ($1,$2,$3,$4,$5,'candidate',now()) RETURNING id",
    )
    .bind(
        value
            .get("tenant_id")
            .and_then(Value::as_str)
            .unwrap_or("default"),
    )
    .bind(name)
    .bind(version)
    .bind(SqlJson(
        value.get("metrics").cloned().unwrap_or_else(|| json!({})),
    ))
    .bind(value.get("signature").and_then(Value::as_str))
    .fetch_one(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    add_audit(
        db,
        "learning",
        "model_add",
        &format!("{id}:{name}@{version}"),
    )
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"ok": true, "id": id, "status": "candidate"})))
}

async fn list_models(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "viewer")?;
    let db = pool(&state)?;
    let active: Option<i64> = sqlx::query_scalar("SELECT active_id FROM model_state WHERE id=1")
        .fetch_one(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let rows = sqlx::query(
        "SELECT id, name, version, metrics, status, created_at::text AS created_at \
         FROM models ORDER BY id DESC",
    )
    .fetch_all(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>("id"),
                "name": r.get::<String, _>("name"),
                "version": r.get::<String, _>("version"),
                "metrics": r.get::<SqlJson<Value>, _>("metrics").0,
                "status": r.get::<String, _>("status"),
                "created_at": r.get::<String, _>("created_at"),
            })
        })
        .collect();
    Ok(Json(json!({"models": out, "active_id": active})))
}

async fn model_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path((model_id, action)): axum::extract::Path<(i64, String)>,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let db = pool(&state)?;
    match action.as_str() {
        "regress" => {
            sqlx::query("UPDATE models SET status='regressed' WHERE id=$1")
                .bind(model_id)
                .execute(db)
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            add_audit(db, "learning", "model_regress", &model_id.to_string())
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        "activate" => {
            let metrics: Option<SqlJson<Value>> =
                sqlx::query_scalar("SELECT metrics FROM models WHERE id=$1")
                    .bind(model_id)
                    .fetch_optional(db)
                    .await
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let Some(SqlJson(metrics)) = metrics else {
                return Err(err(StatusCode::NOT_FOUND, "unknown model"));
            };
            let active: Option<i64> =
                sqlx::query_scalar("SELECT active_id FROM model_state WHERE id=1")
                    .fetch_one(db)
                    .await
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            if let Some(active_id) = active {
                let active_metrics: Option<SqlJson<Value>> =
                    sqlx::query_scalar("SELECT metrics FROM models WHERE id=$1")
                        .bind(active_id)
                        .fetch_optional(db)
                        .await
                        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                if let Some(SqlJson(prev)) = active_metrics {
                    let a = metrics
                        .get("accuracy")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0);
                    let b = prev.get("accuracy").and_then(Value::as_f64).unwrap_or(0.0);
                    if a < b {
                        return Err(err(StatusCode::CONFLICT, "no-regression gate failed"));
                    }
                }
            }
            sqlx::query("UPDATE model_state SET active_id=$1, previous_id=active_id WHERE id=1")
                .bind(model_id)
                .execute(db)
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            if let Some(active_id) = active {
                sqlx::query("UPDATE models SET status='previous' WHERE id=$1")
                    .bind(active_id)
                    .execute(db)
                    .await
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                sqlx::query(
                    "UPDATE models SET status='retired' WHERE status='previous' AND id<>$1",
                )
                .bind(active_id)
                .execute(db)
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            }
            sqlx::query("UPDATE models SET status='active' WHERE id=$1")
                .bind(model_id)
                .execute(db)
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            sqlx::query("UPDATE models SET status='retired' WHERE status='active' AND id<>$1")
                .bind(model_id)
                .execute(db)
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            add_audit(db, "learning", "model_activate", &model_id.to_string())
                .await
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        _ => return Err(err(StatusCode::NOT_FOUND, "unknown action")),
    }
    Ok(Json(json!({"ok": true, "id": model_id, "action": action})))
}

async fn model_rollback(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    auth(&headers, &state, "admin")?;
    let db = pool(&state)?;
    let row = sqlx::query("SELECT active_id, previous_id FROM model_state WHERE id=1")
        .fetch_one(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let active: Option<i64> = row.get("active_id");
    let previous: Option<i64> = row.get("previous_id");
    let Some(previous_id) = previous else {
        return Err(err(StatusCode::CONFLICT, "no previous model"));
    };
    sqlx::query("UPDATE model_state SET active_id=$1, previous_id=$2 WHERE id=1")
        .bind(previous_id)
        .bind(active)
        .execute(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some(active_id) = active {
        sqlx::query("UPDATE models SET status='previous' WHERE id=$1")
            .bind(active_id)
            .execute(db)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        sqlx::query("UPDATE models SET status='retired' WHERE status='previous' AND id<>$1")
            .bind(active_id)
            .execute(db)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    sqlx::query("UPDATE models SET status='active' WHERE id=$1")
        .bind(previous_id)
        .execute(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    sqlx::query("UPDATE models SET status='retired' WHERE status='active' AND id<>$1")
        .bind(previous_id)
        .execute(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    add_audit(db, "learning", "model_rollback", &previous_id.to_string())
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"ok": true, "active_id": previous_id})))
}

async fn enrol(State(state): State<AppState>, body: Bytes) -> Result<Json<Value>, ApiError> {
    let db = pool(&state)?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("json: {e}")))?;
    let token = value
        .get("enrolment_token")
        .and_then(Value::as_str)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "enrolment_token required"))?;
    let pubkey = value
        .get("pubkey")
        .and_then(Value::as_str)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "pubkey required"))?;
    parse_public_key(pubkey)?;

    let mut tx = db
        .begin()
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row = sqlx::query("SELECT tenant_id, used_at FROM enrol_tokens WHERE token = $1")
        .bind(token)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(row) = row else {
        return Err(err(StatusCode::FORBIDDEN, "invalid enrolment token"));
    };
    if row
        .get::<Option<chrono::DateTime<chrono::Utc>>, _>("used_at")
        .is_some()
    {
        return Err(err(StatusCode::FORBIDDEN, "enrolment token already used"));
    }
    let tenant_id: String = row.get("tenant_id");
    let agent_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents(id, tenant_id, hostname, os, arch, agent_version, status, \
         last_seen, enrolled_at, pubkey) VALUES ($1,$2,$3,$4,$5,$6,'healthy',now(),now(),$7)",
    )
    .bind(agent_id)
    .bind(&tenant_id)
    .bind(
        value
            .get("hostname")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
    )
    .bind(value.get("os").and_then(Value::as_str).unwrap_or("unknown"))
    .bind(
        value
            .get("arch")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
    )
    .bind(
        value
            .get("agent_version")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
    )
    .bind(pubkey)
    .execute(&mut *tx)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    sqlx::query("UPDATE enrol_tokens SET used_at = now() WHERE token = $1")
        .bind(token)
        .execute(&mut *tx)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"agent_id": agent_id, "tenant_id": tenant_id})))
}

async fn signed_agent(
    db: &PgPool,
    headers: &HeaderMap,
    body: &[u8],
    value: &Value,
) -> Result<(Uuid, String, bool), ApiError> {
    let agent_id = parse_uuid(value, "agent_id")?;
    let row = sqlx::query("SELECT pubkey, isolated FROM agents WHERE id = $1")
        .bind(agent_id)
        .fetch_optional(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(row) = row else {
        return Err(err(StatusCode::NOT_FOUND, "unknown agent"));
    };
    let pubkey: String = row.get("pubkey");
    let isolated: bool = row.get("isolated");
    verify_body(headers, body, &pubkey)?;
    Ok((agent_id, pubkey, isolated))
}

async fn heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let db = pool(&state)?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("json: {e}")))?;
    let (agent_id, _, isolated) = signed_agent(db, &headers, &body, &value).await?;
    let nonce = value
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "nonce required"))?;
    let inserted = sqlx::query(
        "INSERT INTO nonces(nonce, seen_at) VALUES ($1, now()) \
                                ON CONFLICT (nonce) DO NOTHING",
    )
    .bind(nonce)
    .execute(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if inserted.rows_affected() == 0 {
        return Err(err(StatusCode::CONFLICT, "replayed nonce"));
    }
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    sqlx::query("UPDATE agents SET status = $1, last_seen = now() WHERE id = $2")
        .bind(status)
        .bind(agent_id)
        .execute(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"ok": true, "isolated": isolated})))
}

async fn inventory(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let db = pool(&state)?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("json: {e}")))?;
    let (agent_id, _, _) = signed_agent(db, &headers, &body, &value).await?;
    sqlx::query(
        "UPDATE agents SET os = COALESCE($1, os), arch = COALESCE($2, arch), \
         agent_version = COALESCE($3, agent_version), last_seen = now() WHERE id = $4",
    )
    .bind(value.get("os").and_then(Value::as_str))
    .bind(value.get("arch").and_then(Value::as_str))
    .bind(value.get("agent_version").and_then(Value::as_str))
    .bind(agent_id)
    .execute(db)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"ok": true})))
}

async fn reports(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let db = pool(&state)?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("json: {e}")))?;
    let reports = value
        .get("reports")
        .and_then(Value::as_array)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "reports[] required"))?;
    let Some(first) = reports.first() else {
        return Err(err(StatusCode::BAD_REQUEST, "reports[] empty"));
    };
    let (agent_id, _, _) = signed_agent(db, &headers, &body, first).await?;
    let mut acked = Vec::new();
    for report in reports {
        let Some(report_id) = report.get("report_id").and_then(Value::as_str) else {
            continue;
        };
        let payload = report.get("payload").cloned().unwrap_or_else(|| json!({}));
        sqlx::query(
            "INSERT INTO reports(report_id, tenant_id, agent_id, priority, kind, payload, \
             created_at, ack_at) VALUES ($1,$2,$3,$4,$5,$6,now(),now()) \
             ON CONFLICT (report_id) DO NOTHING",
        )
        .bind(report_id)
        .bind(
            report
                .get("tenant_id")
                .and_then(Value::as_str)
                .unwrap_or("default"),
        )
        .bind(agent_id)
        .bind(
            report
                .get("priority")
                .and_then(Value::as_str)
                .unwrap_or("P3"),
        )
        .bind(report.get("kind").and_then(Value::as_str).unwrap_or(""))
        .bind(SqlJson(payload))
        .execute(db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        acked.push(report_id.to_string());
    }
    Ok(Json(json!({"schema_version": "stml/v0", "acked": acked})))
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    let db = match &state.pool {
        Some(pool) => match sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(pool)
            .await
        {
            Ok(_) => "ok",
            Err(_) => "error",
        },
        None => "not_configured",
    };
    Json(
        json!({"ok": true, "service": "stml", "impl": "rust-p3", "db": db,
                "production_ready": false}),
    )
}

async fn agents(State(state): State<AppState>) -> Json<Value> {
    let Some(pool) = &state.pool else {
        return Json(json!({"agents": [], "note": "database not configured"}));
    };
    match sqlx::query(
        "SELECT id::text AS id, tenant_id, hostname, os, arch, agent_version, status, \
         last_seen::text AS last_seen, isolated, policy_version FROM agents ORDER BY hostname",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => {
            let agents: Vec<Value> = rows
                .into_iter()
                .map(|row| {
                    json!({
                        "id": row.get::<String, _>("id"),
                        "tenant_id": row.get::<String, _>("tenant_id"),
                        "hostname": row.get::<String, _>("hostname"),
                        "os": row.get::<String, _>("os"),
                        "arch": row.get::<String, _>("arch"),
                        "agent_version": row.get::<String, _>("agent_version"),
                        "status": row.get::<String, _>("status"),
                        "last_seen": row.get::<String, _>("last_seen"),
                        "isolated": row.get::<bool, _>("isolated"),
                        "policy_version": row.get::<Option<String>, _>("policy_version"),
                    })
                })
                .collect();
            Json(json!({"agents": agents}))
        }
        Err(e) => Json(json!({"agents": [], "error": e.to_string()})),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let pool = match std::env::var("DATABASE_URL") {
        Ok(url) => {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&url)
                .await?;
            tracing::info!("postgres connected");
            Some(pool)
        }
        Err(_) => {
            tracing::warn!("DATABASE_URL not set; running without DB");
            None
        }
    };

    let policy_pubkey = std::env::var("STML_POLICY_PUBKEY").unwrap_or_else(|_| {
        std::env::var("STML_POLICY_PUBKEY_FILE")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_default()
    });
    let app = Router::new()
        .route("/health", get(health))
        .route("/v0/agents", get(agents))
        .route("/v0/enrol", post(enrol))
        .route("/v0/heartbeat", post(heartbeat))
        .route("/v0/inventory", post(inventory))
        .route("/v0/reports", post(reports))
        .route("/v0/policies", get(list_policies).post(add_policy))
        .route("/v0/approvals", get(list_approvals))
        .route("/v0/approvals/{id}/{action}", post(decide_approval))
        .route("/v0/rollouts", post(start_rollout))
        .route("/v0/rollouts/{id}", get(get_rollout))
        .route("/v0/rollouts/{id}/{action}", post(rollout_action))
        .route("/v0/trust/keys", get(list_keys).post(create_key))
        .route("/v0/trust/keys/{id}/{action}", post(key_action))
        .route("/v0/tls/revoke", post(revoke_cert))
        .route("/v0/tls/revoked", get(list_revoked))
        .route("/v0/audit/verify", get(verify_audit))
        .route("/v0/telemetry", post(telemetry))
        .route("/v0/cases", get(list_cases).post(add_case))
        .route("/v0/models", get(list_models).post(add_model))
        .route("/v0/models/rollback", post(model_rollback))
        .route("/v0/models/{id}/{action}", post(model_action))
        .with_state(AppState {
            pool,
            admin_token: std::env::var("STML_ADMIN_TOKEN").unwrap_or_default(),
            viewer_token: std::env::var("STML_VIEWER_TOKEN").unwrap_or_default(),
            approver_token: std::env::var("STML_APPROVER_TOKEN").unwrap_or_default(),
            policy_pubkey,
            require_approval: std::env::var("STML_REQUIRE_APPROVAL").unwrap_or_else(|_| "1".into())
                != "0",
            trust_dir: std::env::var("STML_TRUST_DIR").unwrap_or_else(|_| "stml-trust".into()),
        });

    let addr = std::env::var("STML_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("stml-server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
