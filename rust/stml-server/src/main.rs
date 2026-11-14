//! STML server scaffold (Rust/axum + optional PostgreSQL).
//!
//! Phase A: `/health` (with DB probe) and read-only `/v0/agents`. Python
//! reference remains authoritative until API parity is implemented.

use axum::{extract::State, routing::get, Json, Router};
use serde_json::{json, Value};

#[cfg(feature = "postgres")]
use sqlx::{postgres::PgPoolOptions, Row};

#[cfg(feature = "postgres")]
#[derive(Clone)]
struct AppState {
    pool: Option<sqlx::PgPool>,
}

#[cfg(not(feature = "postgres"))]
#[derive(Clone)]
struct AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    #[cfg(feature = "postgres")]
    let state = {
        let pool = match std::env::var("DATABASE_URL") {
            Ok(url) => {
                let pool = PgPoolOptions::new().max_connections(5).connect(&url).await?;
                tracing::info!("postgres connected");
                Some(pool)
            }
            Err(_) => {
                tracing::warn!("DATABASE_URL not set; running without DB");
                None
            }
        };
        AppState { pool }
    };
    #[cfg(not(feature = "postgres"))]
    let state = AppState;

    let app = Router::new()
        .route("/health", get(health))
        .route("/v0/agents", get(agents))
        .with_state(state);

    let addr = std::env::var("STML_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("stml-server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    #[cfg(feature = "postgres")]
    let db = match &state.pool {
        Some(pool) => match sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(pool).await {
            Ok(_) => "ok",
            Err(_) => "error",
        },
        None => "not_configured",
    };
    #[cfg(not(feature = "postgres"))]
    let db = {
        let _ = &state;
        "feature_disabled"
    };
    Json(json!({
        "ok": true,
        "service": "stml",
        "impl": "rust-scaffold",
        "db": db,
        "production_ready": false
    }))
}

async fn agents(State(state): State<AppState>) -> Json<Value> {
    #[cfg(feature = "postgres")]
    if let Some(pool) = &state.pool {
        let rows = sqlx::query(
            "SELECT id::text AS id, tenant_id, hostname, os, arch, agent_version, status, \
             last_seen::text AS last_seen, isolated, policy_version \
             FROM agents ORDER BY hostname",
        )
        .fetch_all(pool)
        .await;
        return match rows {
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
            Err(err) => Json(json!({"agents": [], "error": err.to_string()})),
        };
    }
    #[cfg(not(feature = "postgres"))]
    let _ = &state;
    Json(json!({"agents": [], "note": "postgres feature disabled"}))
}
