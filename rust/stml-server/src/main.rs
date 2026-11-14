//! STML server scaffold (Rust/axum).
//!
//! Phase A: only `/health` and a read-only agents placeholder. The Python
//! reference remains authoritative until the PostgreSQL adapter and API parity
//! are implemented (see `docs/rust-postgres-port.md`).

use axum::{routing::get, Json, Router};
use serde_json::{json, Value};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let app = Router::new()
        .route("/health", get(health))
        .route("/v0/agents", get(agents));

    let addr = std::env::var("STML_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("stml-server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<Value> {
    Json(json!({
        "ok": true,
        "service": "stml",
        "impl": "rust-scaffold",
        "production_ready": false
    }))
}

async fn agents() -> Json<Value> {
    // TODO(Phase B): PostgreSQL-backed registry + authn/authz.
    Json(json!({"agents": [], "note": "rust scaffold: PostgreSQL adapter pending"}))
}
