use std::path::PathBuf;

use aidf_core::ml::{OnnxModel, OrtModel};
use serde_json::Value;

fn data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name)
}

#[test]
fn holdout_50_rows_match_onnxruntime() {
    let text = std::fs::read_to_string(data_path("pe_holdout_50.json")).unwrap();
    let payload: Value = serde_json::from_str(&text).unwrap();
    let rows: Vec<Vec<f32>> = payload["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            row.as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_f64().unwrap() as f32)
                .collect()
        })
        .collect();
    let expected: Vec<f64> = payload["scores"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_f64().unwrap())
        .collect();
    assert_eq!(rows.len(), 50);
    assert_eq!(rows[0].len(), 2381);

    let model = OnnxModel::new(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("spikes")
            .join("06-ml")
            .join("pe_model.onnx"),
    )
    .unwrap();
    let actual = model.predict(&rows).unwrap();
    assert_eq!(actual.len(), expected.len());
    let max_diff = actual
        .iter()
        .zip(&expected)
        .map(|(a, b)| (a - b).abs())
        .fold(0.0_f64, f64::max);
    assert!(max_diff <= 1e-4, "max_diff={max_diff}");
}

#[test]
fn ort_holdout_50_rows_match_onnxruntime() {
    let text = std::fs::read_to_string(data_path("pe_holdout_50.json")).unwrap();
    let payload: Value = serde_json::from_str(&text).unwrap();
    let rows: Vec<Vec<f32>> = payload["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            row.as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_f64().unwrap() as f32)
                .collect()
        })
        .collect();
    let expected: Vec<f64> = payload["scores"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_f64().unwrap())
        .collect();
    let mut model = OrtModel::new(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("spikes")
            .join("06-ml")
            .join("pe_model.onnx"),
    )
    .unwrap();
    let actual = model.predict(&rows).unwrap();
    let max_diff = actual
        .iter()
        .zip(&expected)
        .map(|(a, b)| (a - b).abs())
        .fold(0.0_f64, f64::max);
    assert!(max_diff <= 1e-4, "max_diff={max_diff}");
}
