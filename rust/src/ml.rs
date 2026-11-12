//! ONNX shadow inference — Rust port of `core/ml.py` (stage 8).
//!
//! Shadow means the model emits verdicts/metrics but never triggers an action.
//! `MODELS_TRAIN_ON_DEVICE=False`: only pre-trained, signed artifacts.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};
use tract_onnx::prelude::*;
use tract_onnx::tract_core::dims;

use crate::types::{Detector, Severity, Verdict};

pub const SEVERITY_BANDS: [(f64, &str); 4] = [
    (0.99, "critical"),
    (0.9, "high"),
    (0.5, "medium"),
    (0.0, "low"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlError(pub String);

impl fmt::Display for MlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MlError {}

/// Score threshold that yields at most `target_fpr` false positives.
/// Linear interpolation matches `numpy.quantile` default.
pub fn fpr_threshold(benign_scores: &[f64], target_fpr: f64) -> Result<f64, MlError> {
    if benign_scores.is_empty() {
        return Err(MlError("need benign scores to calibrate".to_owned()));
    }
    if !(target_fpr > 0.0 && target_fpr < 1.0) {
        return Err(MlError("target_fpr must be within (0, 1)".to_owned()));
    }
    let mut sorted = benign_scores.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let q = 1.0 - target_fpr;
    let position = (sorted.len() - 1) as f64 * q;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        Ok(sorted[lower])
    } else {
        let weight = position - lower as f64;
        Ok(sorted[lower] * (1.0 - weight) + sorted[upper] * weight)
    }
}

pub fn severity_for(score: f64) -> Severity {
    for (bound, severity) in SEVERITY_BANDS {
        if score >= bound {
            return Severity::parse(severity).unwrap_or(Severity::Low);
        }
    }
    Severity::Low
}

pub struct OnnxModel {
    pub path: PathBuf,
    runnable: Arc<TypedRunnableModel>,
    pub load_ms: f64,
    pub input_features: usize,
}

impl OnnxModel {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, MlError> {
        Self::with_features(path, 2381)
    }

    pub fn with_features(path: impl AsRef<Path>, features: usize) -> Result<Self, MlError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(MlError(format!("model not found: {}", path.display())));
        }
        let started = Instant::now();
        let model = tract_onnx::onnx()
            .model_for_path(&path)
            .map_err(|error| MlError(error.to_string()))?;
        let batch = model.sym("N");
        let model = model
            .with_input_fact(0, f32::fact(dims!(batch, features)).into())
            .map_err(|error| MlError(error.to_string()))?
            .into_optimized()
            .map_err(|error| MlError(error.to_string()))?
            .into_runnable()
            .map_err(|error| MlError(error.to_string()))?;
        Ok(Self {
            path,
            runnable: model,
            load_ms: round3(started.elapsed().as_secs_f64() * 1000.0),
            input_features: features,
        })
    }

    pub fn size_mb(&self) -> f64 {
        std::fs::metadata(&self.path)
            .map(|meta| round2(meta.len() as f64 / 1e6))
            .unwrap_or(0.0)
    }

    pub fn predict(&self, rows: &[Vec<f32>]) -> Result<Vec<f64>, MlError> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let width = rows[0].len();
        if rows.iter().any(|row| row.len() != width) {
            return Err(MlError("ragged feature rows".to_owned()));
        }
        let mut flat = Vec::with_capacity(rows.len() * width);
        for row in rows {
            flat.extend_from_slice(row);
        }
        let input = Tensor::from_shape(&[rows.len(), width], &flat)
            .map_err(|error| MlError(error.to_string()))?;
        let outputs = self
            .runnable
            .run(tvec!(input.into_tvalue()))
            .map_err(|error| MlError(error.to_string()))?;
        let mut result = Vec::new();
        let mut found = false;
        for output in &outputs {
            let Ok(view) = output.to_plain_array_view::<f32>() else {
                continue;
            };
            if view.ndim() == 2 && view.shape()[1] >= 2 {
                result = view
                    .axis_iter(tract_ndarray::Axis(0))
                    .map(|row| row[1] as f64)
                    .collect();
                found = true;
                break;
            }
        }
        if !found {
            let output = outputs
                .first()
                .ok_or_else(|| MlError("model returned no outputs".to_owned()))?;
            let view = output
                .to_plain_array_view::<f32>()
                .map_err(|error| MlError(error.to_string()))?;
            result = view.iter().map(|value| *value as f64).collect();
        }
        Ok(result)
    }

    pub fn predict_one(&self, features: &[f32]) -> Result<(f64, f64), MlError> {
        let started = Instant::now();
        let scores = self.predict(&[features.to_vec()])?;
        let score = scores.first().copied().unwrap_or(0.0);
        Ok((score, started.elapsed().as_secs_f64() * 1000.0))
    }
}

pub struct ShadowDetector {
    pub model: OnnxModel,
    pub model_id: String,
    pub model_version: String,
    pub threshold: f64,
    pub platform: String,
    pub alerts: u64,
    pub benign_seen: u64,
    pub benign_alerts: u64,
    pub latencies: Vec<f64>,
}

impl ShadowDetector {
    pub fn new(model: OnnxModel, model_id: &str, model_version: &str, threshold: f64) -> Self {
        Self {
            model,
            model_id: model_id.to_owned(),
            model_version: model_version.to_owned(),
            threshold,
            platform: "windows".to_owned(),
            alerts: 0,
            benign_seen: 0,
            benign_alerts: 0,
            latencies: Vec::new(),
        }
    }

    pub fn confidence(&self, score: f64) -> f64 {
        round6(score.clamp(0.0, 1.0))
    }

    pub fn scan(
        &mut self,
        event: &Value,
        features: &[f32],
        ground_truth_malicious: Option<bool>,
    ) -> Result<Option<Verdict>, MlError> {
        let (score, latency_ms) = self.model.predict_one(features)?;
        self.latencies.push(latency_ms);
        if score < self.threshold {
            if ground_truth_malicious == Some(false) {
                self.benign_seen += 1;
            }
            return Ok(None);
        }
        self.alerts += 1;
        if ground_truth_malicious == Some(false) {
            self.benign_seen += 1;
            self.benign_alerts += 1;
        }
        let platform = event
            .get("platform")
            .and_then(Value::as_str)
            .unwrap_or(&self.platform);
        let mut verdict = Verdict::new(
            Detector::FileModel,
            platform,
            self.confidence(score),
            severity_for(score),
            None,
            Some(&self.model_id),
            "ml_shadow_score",
            &format!(
                "shadow file model raw_score={score:.4} confidence={:.4} threshold={}",
                self.confidence(score),
                self.threshold
            ),
        );
        verdict.model_version = Some(self.model_version.clone());
        verdict.trace_id = parse_uuid(event, "trace_id");
        verdict.event_id = parse_uuid(event, "event_id");
        Ok(Some(verdict))
    }

    pub fn stats(&self) -> Value {
        let mut latencies = self.latencies.clone();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let percentile = |p: f64| -> Option<f64> {
            if latencies.is_empty() {
                None
            } else {
                Some(round3(
                    latencies[((latencies.len() as f64 * p) as usize).min(latencies.len() - 1)],
                ))
            }
        };
        json!({
            "alerts": self.alerts,
            "benign_seen": self.benign_seen,
            "benign_alerts": self.benign_alerts,
            "empirical_fpr": if self.benign_seen == 0 { Value::Null } else { json!(round6(self.benign_alerts as f64 / self.benign_seen as f64)) },
            "latency_ms_p50": percentile(0.5),
            "latency_ms_p95": percentile(0.95),
            "latency_ms_p99": percentile(0.99),
            "shadow": true,
        })
    }
}

fn parse_uuid(payload: &Value, key: &str) -> uuid::Uuid {
    payload
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .unwrap_or_else(uuid::Uuid::new_v4)
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn round6(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

/// Fast ONNX Runtime backend (Python-compatible scores, suitable for 50k holdout).
pub struct OrtModel {
    session: ort::session::Session,
    input_name: String,
    output_name: String,
    pub features: usize,
    pub load_ms: f64,
}

impl OrtModel {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, MlError> {
        let started = Instant::now();
        let env = ort::init().build().map_err(|e| MlError(e.to_string()))?;
        let session = ort::session::Session::builder(&env)
            .map_err(|e| MlError(e.to_string()))?
            .commit_from_file(path.as_ref())
            .map_err(|e| MlError(e.to_string()))?;
        Ok(Self {
            session,
            input_name: "input".to_owned(),
            output_name: "probabilities".to_owned(),
            features: 2381,
            load_ms: round3(started.elapsed().as_secs_f64() * 1000.0),
        })
    }

    pub fn predict(&mut self, rows: &[Vec<f32>]) -> Result<Vec<f64>, MlError> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let width = rows[0].len();
        let mut flat = Vec::with_capacity(rows.len() * width);
        for row in rows {
            if row.len() != width {
                return Err(MlError("ragged feature rows".to_owned()));
            }
            flat.extend_from_slice(row);
        }
        let input = ort::value::Tensor::from_array((vec![rows.len(), width], flat))
            .map_err(|e| MlError(e.to_string()))?;
        let outputs = self
            .session
            .run(ort::inputs![self.input_name.as_str() => input])
            .map_err(|e| MlError(e.to_string()))?;
        let output = outputs
            .get(self.output_name.as_str())
            .unwrap_or(&outputs[0]);
        let (shape, data) = output
            .try_extract_tensor::<f32>()
            .map_err(|e| MlError(e.to_string()))?;
        let cols = *shape.last().unwrap_or(&1) as usize;
        if shape.len() >= 2 && cols >= 2 {
            Ok((0..rows.len())
                .map(|row| data[row * cols + 1] as f64)
                .collect())
        } else {
            Ok(data.iter().map(|value| *value as f64).collect())
        }
    }
}
