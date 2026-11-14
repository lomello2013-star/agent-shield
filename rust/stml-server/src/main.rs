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
use sqlx::{postgres::PgPoolOptions, types::Json as SqlJson, PgPool, Row};
use uuid::Uuid;

type ApiError = (StatusCode, Json<Value>);

#[derive(Clone)]
struct AppState {
    pool: Option<PgPool>,
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
        json!({"ok": true, "service": "stml", "impl": "rust-p1", "db": db,
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

    let app = Router::new()
        .route("/health", get(health))
        .route("/v0/agents", get(agents))
        .route("/v0/enrol", post(enrol))
        .route("/v0/heartbeat", post(heartbeat))
        .route("/v0/inventory", post(inventory))
        .route("/v0/reports", post(reports))
        .with_state(AppState { pool });

    let addr = std::env::var("STML_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("stml-server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
