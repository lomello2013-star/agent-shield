use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

use aidf_core::ipc::{PythonRpcServer, RpcRegistry};
use serde_json::json;

#[test]
fn python_multiprocessing_client_interoperates() {
    let mut registry = RpcRegistry::new();
    registry.register("ping", &["viewer", "operator", "admin"], |_| {
        Ok(json!({"pong": true}))
    });
    let tokens: HashMap<String, String> = [("tok".to_owned(), "viewer".to_owned())]
        .into_iter()
        .collect();
    let server =
        PythonRpcServer::bind("127.0.0.1:0", b"secret".to_vec(), tokens, registry).expect("bind");
    let port = server.local_addr().unwrap().port();
    let handle = thread::spawn(move || server.serve());

    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("python_client.py");
    let output = Command::new("python")
        .arg(script)
        .arg(port.to_string())
        .output()
        .expect("run python");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "python failed: {stderr}\nstdout: {stdout}"
    );
    assert!(stdout.contains("'role': 'viewer'"), "stdout={stdout}");
    assert!(stdout.contains("'pong': True"), "stdout={stdout}");
    // The server accept loop is intentionally blocking; process exit ends it.
    drop(handle);
}
