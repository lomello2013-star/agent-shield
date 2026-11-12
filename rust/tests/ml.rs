use std::path::PathBuf;

use aidf_core::ml::{fpr_threshold, severity_for, OnnxModel, ShadowDetector};
use aidf_core::types::Severity;
use serde_json::json;

fn model_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("spikes")
        .join("06-ml")
        .join("pe_model.onnx")
}

#[test]
fn fpr_threshold_matches_linear_quantile() {
    let scores: Vec<f64> = (0..100).map(|value| value as f64).collect();
    assert!((fpr_threshold(&scores, 0.1).unwrap() - 89.1).abs() < 1e-9);
    assert!((fpr_threshold(&scores, 0.5).unwrap() - 49.5).abs() < 1e-9);
    assert!(fpr_threshold(&[], 0.1).is_err());
    assert!(fpr_threshold(&scores, 0.0).is_err());
}

#[test]
fn severity_bands_match_python() {
    assert_eq!(severity_for(0.995), Severity::Critical);
    assert_eq!(severity_for(0.95), Severity::High);
    assert_eq!(severity_for(0.7), Severity::Medium);
    assert_eq!(severity_for(0.1), Severity::Low);
}

#[test]
fn loads_pe_model_and_predicts_zero_vector() {
    let model = OnnxModel::new(model_path()).unwrap();
    assert!(model.size_mb() > 0.0);
    let features = vec![0.0f32; 2381];
    let scores = model.predict(std::slice::from_ref(&features)).unwrap();
    assert_eq!(scores.len(), 1);
    assert!(scores[0].is_finite());
    // Python onnxruntime on the same input returns 0.062291086.
    assert!(
        (scores[0] - 0.062291086).abs() < 1e-4,
        "score={}",
        scores[0]
    );
    let (score, latency) = model.predict_one(&features).unwrap();
    assert!(score.is_finite());
    assert!(latency >= 0.0);
}

#[test]
fn shadow_detector_emits_verdict_and_stats() {
    let model = OnnxModel::new(model_path()).unwrap();
    let mut detector = ShadowDetector::new(model, "pe-ember", "1.0.0", 0.0);
    let event = json!({
        "trace_id": uuid::Uuid::new_v4().to_string(),
        "event_id": uuid::Uuid::new_v4().to_string(),
        "platform": "windows"
    });
    let verdict = detector
        .scan(&event, &vec![0.0f32; 2381], Some(false))
        .unwrap()
        .expect("threshold 0 must alert");
    assert_eq!(verdict.detector, aidf_core::types::Detector::FileModel);
    assert_eq!(verdict.model_id.as_deref(), Some("pe-ember"));
    assert_eq!(verdict.model_version.as_deref(), Some("1.0.0"));
    assert_eq!(detector.alerts, 1);
    assert_eq!(detector.benign_alerts, 1);
    let stats = detector.stats();
    assert_eq!(stats["alerts"].as_u64(), Some(1));
    assert_eq!(stats["shadow"].as_bool(), Some(true));
}
