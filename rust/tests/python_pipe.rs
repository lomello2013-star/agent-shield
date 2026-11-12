#![cfg(windows)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use aidf_core::ipc::{serve_python_pipe, RpcRegistry};
use serde_json::json;
use uuid::Uuid;

#[test]
fn python_multiprocessing_named_pipe_interoperates() {
    let mut registry = RpcRegistry::new();
    registry.register("ping", &["viewer", "operator", "admin"], |_| {
        Ok(json!({"pong": true}))
    });
    let tokens: HashMap<String, String> = [("tok".to_owned(), "viewer".to_owned())]
        .into_iter()
        .collect();
    let pipe_name = format!(r"\\.\pipe\aidf-test-{}", Uuid::new_v4().simple());
    let server_pipe = pipe_name.clone();
    thread::spawn(move || {
        let _ = serve_python_pipe(&server_pipe, b"secret".to_vec(), tokens, registry);
    });
    thread::sleep(Duration::from_millis(300));

    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("python_client.py");
    let mut last = String::new();
    for _ in 0..5 {
        let output = Command::new("python")
            .arg(&script)
            .arg(&pipe_name)
            .output()
            .expect("run python");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() && stdout.contains("'pong': True") {
            assert!(stdout.contains("'role': 'viewer'"), "stdout={stdout}");
            return;
        }
        last = format!(
            "status={:?}\nstdout={stdout}\nstderr={stderr}",
            output.status
        );
        thread::sleep(Duration::from_millis(200));
    }
    panic!("python named-pipe interop failed: {last}");
}
