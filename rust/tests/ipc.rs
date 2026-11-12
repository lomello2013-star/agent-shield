use std::collections::HashMap;
use std::thread;

use aidf_core::ipc::{
    default_address, free_pipe_name, RpcClient, RpcRegistry, RpcServer, FORBIDDEN, METHOD_NOT_FOUND,
};
use serde_json::json;

fn registry() -> RpcRegistry {
    let mut registry = RpcRegistry::new();
    registry.register("ping", &["viewer", "operator", "admin"], |_| {
        Ok(json!({"pong": true}))
    });
    registry.register("shutdown", &["admin"], |_| Ok(json!({"stopping": true})));
    registry.register("echo", &["viewer"], |params| Ok(params.clone()));
    registry
}

#[test]
fn dispatch_enforces_roles_and_errors() {
    let registry = registry();
    let ok = registry.dispatch(
        &json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}),
        "viewer",
    );
    assert_eq!(ok["result"]["pong"], true);

    let forbidden = registry.dispatch(
        &json!({"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": {}}),
        "viewer",
    );
    assert_eq!(forbidden["error"]["code"].as_i64(), Some(FORBIDDEN));

    let unknown = registry.dispatch(
        &json!({"jsonrpc": "2.0", "id": 3, "method": "nope", "params": {}}),
        "admin",
    );
    assert_eq!(unknown["error"]["code"].as_i64(), Some(METHOD_NOT_FOUND));

    let bad = registry.dispatch(&json!({"id": 4, "method": "ping"}), "viewer");
    assert_eq!(bad["error"]["code"].as_i64(), Some(-32600));
}

#[test]
fn server_handshake_roles_and_calls() {
    let address = free_pipe_name("aidf-ipc");
    let tokens: HashMap<String, String> = [
        ("admin-token".to_owned(), "admin".to_owned()),
        ("viewer-token".to_owned(), "viewer".to_owned()),
    ]
    .into_iter()
    .collect();
    let server = RpcServer::new(&address, tokens, registry());
    server.start().unwrap();

    let mut client = RpcClient::connect(&address, "viewer-token").unwrap();
    assert_eq!(client.role, "viewer");
    assert!(client.methods.contains(&"ping".to_owned()));
    assert_eq!(client.call("ping", json!({})).unwrap()["pong"], true);
    assert!(client.call("shutdown", json!({})).is_err());
    client.close();

    let mut admin = RpcClient::connect(&address, "admin-token").unwrap();
    assert_eq!(admin.role, "admin");
    assert_eq!(admin.call("shutdown", json!({})).unwrap()["stopping"], true);
    admin.close();
    server.stop();
}

#[test]
fn bad_token_is_rejected() {
    let address = free_pipe_name("aidf-ipc-bad");
    let tokens: HashMap<String, String> = [("good".to_owned(), "viewer".to_owned())]
        .into_iter()
        .collect();
    let server = RpcServer::new(&address, tokens, registry());
    server.start().unwrap();
    assert!(RpcClient::connect(&address, "wrong").is_err());
    server.stop();
}

#[test]
fn concurrent_clients_all_get_pong() {
    let address = free_pipe_name("aidf-ipc-concurrent");
    let tokens: HashMap<String, String> = [("token".to_owned(), "admin".to_owned())]
        .into_iter()
        .collect();
    let server = RpcServer::new(&address, tokens, registry());
    server.start().unwrap();
    let mut workers = Vec::new();
    for _ in 0..3 {
        let address = address.clone();
        workers.push(thread::spawn(move || {
            let mut client = RpcClient::connect(&address, "token").unwrap();
            let response = client.call("ping", json!({})).unwrap();
            client.close();
            response["pong"].as_bool()
        }));
    }
    for worker in workers {
        assert_eq!(worker.join().unwrap(), Some(true));
    }
    server.stop();
}

#[test]
fn address_helper_is_stable() {
    assert_eq!(default_address("aidf"), "aidf.sock");
}
