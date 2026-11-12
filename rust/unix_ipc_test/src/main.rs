#[path = "../../src/ipc.rs"]
mod ipc;

use std::collections::HashMap;
use std::process::Command;
use std::thread;
use std::time::Duration;

use serde_json::json;

fn main() {
    let mut registry = ipc::RpcRegistry::new();
    registry.register("ping", &["viewer", "operator", "admin"], |_| {
        Ok(json!({"pong": true}))
    });
    let tokens: HashMap<String, String> = [("tok".to_owned(), "viewer".to_owned())]
        .into_iter()
        .collect();
    let socket = format!("/tmp/aidf-unix-test-{}.sock", std::process::id());
    let server = ipc::PythonUnixRpcServer::bind(&socket, b"secret".to_vec(), tokens, registry)
        .expect("bind unix socket");
    thread::spawn(move || server.serve());
    thread::sleep(Duration::from_millis(200));

    let script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("python_client.py");
    let output = Command::new("python3")
        .arg(script)
        .arg(&socket)
        .output()
        .expect("run python3");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() || !stdout.contains("'pong': True") {
        eprintln!("status={:?}\nstdout={stdout}\nstderr={stderr}", output.status);
        std::process::exit(1);
    }
    println!("AF_UNIX python interop ok: {stdout}");
}
