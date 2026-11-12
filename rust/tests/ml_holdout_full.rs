use std::path::PathBuf;

use aidf_core::ml::OrtModel;
use serde_json::json;

const FEATURES: usize = 2381;
const TOTAL: usize = 50_000;
const BATCH: usize = 1_000;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("pe_holdout_50k")
}

#[test]
fn full_50k_holdout_with_ort() {
    let rows_path = root().join("rows.f32");
    let scores_path = root().join("scores.f32");
    if !rows_path.exists() || !scores_path.exists() {
        eprintln!("skip: run the Python exporter first (target/pe_holdout_50k)");
        return;
    }
    let rows_bytes = std::fs::read(&rows_path).unwrap();
    let scores_bytes = std::fs::read(&scores_path).unwrap();
    let expected_count = scores_bytes.len() / 4;
    assert_eq!(expected_count, TOTAL);
    assert_eq!(rows_bytes.len(), TOTAL * FEATURES * 4);

    let state_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("artifacts")
        .join("rust_ml_holdout_state.json");
    let mut start = 0usize;
    let mut previous_max = 0.0f64;
    if std::env::var("AIDF_ML_RESUME").as_deref() == Ok("1") {
        if let Ok(text) = std::fs::read_to_string(&state_path) {
            if let Ok(state) = serde_json::from_str::<serde_json::Value>(&text) {
                start = state["processed"].as_u64().unwrap_or(0) as usize;
                previous_max = state["max_diff"].as_f64().unwrap_or(0.0);
            }
        }
    }

    let mut model = OrtModel::new(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("spikes")
            .join("06-ml")
            .join("pe_model.onnx"),
    )
    .unwrap();

    let mut processed = start;
    let mut max_diff = previous_max;
    while processed < TOTAL {
        let end = (processed + BATCH).min(TOTAL);
        let mut rows = Vec::with_capacity(end - processed);
        for row in processed..end {
            let base = row * FEATURES * 4;
            let values: Vec<f32> = rows_bytes[base..base + FEATURES * 4]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|chunk| f32::from_le_bytes(*chunk))
                .collect();
            rows.push(values);
        }
        let actual = model.predict(&rows).unwrap();
        for (offset, score) in actual.iter().enumerate() {
            let row = processed + offset;
            let base = row * 4;
            let expected = f32::from_le_bytes([
                scores_bytes[base],
                scores_bytes[base + 1],
                scores_bytes[base + 2],
                scores_bytes[base + 3],
            ]) as f64;
            max_diff = max_diff.max((score - expected).abs());
        }
        processed = end;
        let state = json!({
            "processed": processed,
            "total": TOTAL,
            "max_diff": max_diff,
            "updated_at": chrono::Utc::now().to_rfc3339(),
        });
        std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
        eprintln!("processed {processed}/{TOTAL}, max_diff={max_diff:.9}");
    }

    assert!(max_diff <= 1e-4, "max_diff={max_diff}");
    let report = json!({
        "rows": TOTAL,
        "features": FEATURES,
        "backend": "ort",
        "max_abs_diff": max_diff,
        "tolerance": 1e-4,
        "status": "ok",
        "completed_at": chrono::Utc::now().to_rfc3339(),
    });
    let report_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("artifacts")
        .join("rust_ml_holdout_report.json");
    std::fs::write(report_path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}
