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
use ed25519_dalek::{Signature, VerifyingKey};
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
        json!({"ok": true, "service": "stml", "impl": "rust-p2", "db": db,
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
        .with_state(AppState {
            pool,
            admin_token: std::env::var("STML_ADMIN_TOKEN").unwrap_or_default(),
            viewer_token: std::env::var("STML_VIEWER_TOKEN").unwrap_or_default(),
            approver_token: std::env::var("STML_APPROVER_TOKEN").unwrap_or_default(),
            policy_pubkey,
            require_approval: std::env::var("STML_REQUIRE_APPROVAL").unwrap_or_else(|_| "1".into())
                != "0",
        });

    let addr = std::env::var("STML_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("stml-server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
