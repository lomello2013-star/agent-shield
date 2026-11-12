//! JSON-RPC 2.0 IPC — Rust port of the dispatch/authorisation semantics from
//! `core/ipc.py`.
//!
//! Transport: `interprocess` local sockets (named pipe on Windows, AF_UNIX on
//! Linux), framing: one JSON object per line. The Python reference uses
//! `multiprocessing.connection` authkey + pickle framing; this transport is
//! **not wire-compatible** with it (documented in `rust/README.md`).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use interprocess::local_socket::{prelude::*, GenericNamespaced, ListenerOptions, Stream};
use serde_json::{json, Value};
use uuid::Uuid;

pub const MAX_MESSAGE: usize = 1 << 20;
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
pub const UNAUTHORIZED: i64 = -32001;
pub const FORBIDDEN: i64 = -32002;

#[derive(Clone, Debug, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Value,
}

impl RpcError {
    pub fn new(code: i64, message: &str) -> Self {
        Self {
            code,
            message: message.to_owned(),
            data: Value::Null,
        }
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

type Handler = Arc<dyn Fn(&Value) -> Result<Value, RpcError> + Send + Sync>;

#[derive(Clone)]
pub struct RpcRegistry {
    handlers: HashMap<String, (HashSet<String>, Handler)>,
}

impl Default for RpcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RpcRegistry {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    pub fn register<F>(&mut self, name: &str, roles: &[&str], handler: F)
    where
        F: Fn(&Value) -> Result<Value, RpcError> + Send + Sync + 'static,
    {
        if roles.is_empty() {
            return;
        }
        self.handlers.insert(
            name.to_owned(),
            (
                roles.iter().map(|role| (*role).to_owned()).collect(),
                Arc::new(handler),
            ),
        );
    }

    pub fn methods_for(&self, role: &str) -> Vec<String> {
        let mut methods: Vec<String> = self
            .handlers
            .iter()
            .filter(|(_, (roles, _))| roles.contains(role))
            .map(|(name, _)| name.clone())
            .collect();
        methods.sort();
        methods
    }

    pub fn dispatch(&self, request: &Value, role: &str) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let error = |code: i64, message: &str| json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}});
        let Some(object) = request.as_object() else {
            return error(INVALID_REQUEST, "request must be an object");
        };
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return error(INVALID_REQUEST, "jsonrpc must be '2.0'");
        }
        if !object.contains_key("id") {
            return error(INVALID_REQUEST, "missing id");
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return error(INVALID_REQUEST, "missing method");
        };
        if method.is_empty() {
            return error(INVALID_REQUEST, "missing method");
        }
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        let params = if params.is_null() { json!({}) } else { params };
        if !params.is_object() {
            return error(INVALID_PARAMS, "params must be an object");
        }
        let Some((allowed, handler)) = self.handlers.get(method) else {
            return error(METHOD_NOT_FOUND, &format!("unknown method: {method}"));
        };
        if !allowed.contains(role) {
            return error(FORBIDDEN, &format!("role {role:?} may not call {method:?}"));
        }
        match handler(&params) {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(error) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": error.code, "message": error.message, "data": error.data}
            }),
        }
    }
}

pub struct RpcServer {
    address: String,
    tokens: HashMap<String, String>,
    registry: Arc<RpcRegistry>,
    stop: Arc<AtomicBool>,
}

impl RpcServer {
    pub fn new(address: &str, tokens: HashMap<String, String>, registry: RpcRegistry) -> Self {
        Self {
            address: address.to_owned(),
            tokens,
            registry: Arc::new(registry),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&self) -> std::io::Result<()> {
        let name = self
            .address
            .clone()
            .to_ns_name::<GenericNamespaced>()
            .map_err(std::io::Error::other)?;
        let listener = ListenerOptions::new().name(name).create_sync()?;
        let tokens = self.tokens.clone();
        let registry = Arc::clone(&self.registry);
        let stop = Arc::clone(&self.stop);
        thread::spawn(move || {
            for connection in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(connection) = connection else {
                    break;
                };
                let tokens = tokens.clone();
                let registry = Arc::clone(&registry);
                thread::spawn(move || handle_connection(connection, tokens, registry));
            }
        });
        Ok(())
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn handle_connection(
    connection: Stream,
    tokens: HashMap<String, String>,
    registry: Arc<RpcRegistry>,
) {
    let mut reader = BufReader::new(connection);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.len() > MAX_MESSAGE {
        return;
    }
    let hello: Value = match serde_json::from_str(&line) {
        Ok(value) => value,
        Err(_) => {
            let _ = reader.get_mut().write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"parse error\"}}\n",
            );
            return;
        }
    };
    if hello.get("method").and_then(Value::as_str) != Some("hello") {
        let _ = write_error(reader.get_mut(), UNAUTHORIZED, "hello required");
        return;
    }
    let token = hello
        .get("params")
        .and_then(|params| params.get("token"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(role) = tokens.get(token) else {
        let _ = write_error(reader.get_mut(), UNAUTHORIZED, "bad token");
        return;
    };
    let response = json!({
        "jsonrpc": "2.0",
        "id": hello.get("id").cloned().unwrap_or(Value::Null),
        "result": {"role": role, "methods": registry.methods_for(role)}
    });
    if write_json(reader.get_mut(), &response).is_err() {
        return;
    }
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line.len() > MAX_MESSAGE => {
                let _ = write_error(reader.get_mut(), INVALID_REQUEST, "request too large");
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => {
                let _ = write_error(reader.get_mut(), PARSE_ERROR, "unreadable frame");
                break;
            }
        };
        let response = registry.dispatch(&request, role);
        if write_json(reader.get_mut(), &response).is_err() {
            break;
        }
    }
}

fn write_error(stream: &mut Stream, code: i64, message: &str) -> std::io::Result<()> {
    write_json(
        stream,
        &json!({"jsonrpc": "2.0", "id": null, "error": {"code": code, "message": message}}),
    )
}

fn write_json(stream: &mut Stream, value: &Value) -> std::io::Result<()> {
    let line = serde_json::to_string(value).unwrap_or_default();
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

pub struct RpcClient {
    reader: BufReader<Stream>,
    next_id: u64,
    pub role: String,
    pub methods: Vec<String>,
}

impl RpcClient {
    pub fn connect(address: &str, token: &str) -> std::io::Result<Self> {
        let name = address
            .to_owned()
            .to_ns_name::<GenericNamespaced>()
            .map_err(std::io::Error::other)?;
        let stream = Stream::connect(name)?;
        let mut client = Self {
            reader: BufReader::new(stream),
            next_id: 0,
            role: String::new(),
            methods: Vec::new(),
        };
        let hello = client.call_raw("hello", json!({"token": token}))?;
        client.role = hello
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        client.methods = hello
            .get("methods")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(client)
    }

    fn call_raw(&mut self, method: &str, params: Value) -> std::io::Result<Value> {
        self.next_id += 1;
        let request = json!({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
            "params": params
        });
        write_json(self.reader.get_mut(), &request)?;
        let mut line = String::new();
        self.reader.read_line(&mut line)?;
        let response: Value = serde_json::from_str(&line)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if let Some(error) = response.get("error") {
            return Err(std::io::Error::other(format!(
                "{}: {}",
                error
                    .get("code")
                    .and_then(Value::as_i64)
                    .unwrap_or(INTERNAL_ERROR),
                error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("rpc error")
            )));
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }

    pub fn call(&mut self, method: &str, params: Value) -> std::io::Result<Value> {
        self.call_raw(method, params)
    }

    pub fn close(self) {
        drop(self.reader);
    }
}

pub fn generate_token() -> String {
    Uuid::new_v4().simple().to_string()
}

pub fn default_address(name: &str) -> String {
    format!("{name}.sock")
}

pub fn free_pipe_name(prefix: &str) -> String {
    default_address(&format!("{prefix}-{}", Uuid::new_v4().simple()))
}

// ---------------------------------------------------------------------------
// Python `multiprocessing.connection` wire compatibility (TCP transport)
// ---------------------------------------------------------------------------

use std::io::Read;
use std::net::TcpListener;

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const PY_CHALLENGE: &[u8] = b"#CHALLENGE#";
const PY_WELCOME: &[u8] = b"#WELCOME#";
const PY_FAILURE: &[u8] = b"#FAILURE#";

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn read_frame<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let size = i32::from_be_bytes(header);
    if size < 0 || size as usize > MAX_MESSAGE {
        return Err(std::io::Error::other("bad frame size"));
    }
    let mut payload = vec![0u8; size as usize];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

fn write_frame<W: Write>(stream: &mut W, payload: &[u8]) -> std::io::Result<()> {
    if payload.len() > MAX_MESSAGE {
        return Err(std::io::Error::other("frame too large"));
    }
    // One WriteFile call is required for message-mode named pipes: Python reads
    // the 4-byte header and payload as parts of the same message.
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&(payload.len() as i32).to_be_bytes());
    framed.extend_from_slice(payload);
    stream.write_all(&framed)?;
    stream.flush()
}

fn python_deliver_challenge<S: Read + Write>(
    stream: &mut S,
    authkey: &[u8],
) -> std::io::Result<()> {
    let mut random = [0u8; 40];
    OsRng.fill_bytes(&mut random);
    let mut message = b"{sha256}".to_vec();
    message.extend_from_slice(&random);
    let mut framed = PY_CHALLENGE.to_vec();
    framed.extend_from_slice(&message);
    write_frame(stream, &framed)?;
    let response = read_frame(stream)?;
    let mut expected = b"{sha256}".to_vec();
    expected.extend_from_slice(&hmac_sha256(authkey, &message));
    if response != expected {
        let _ = write_frame(stream, PY_FAILURE);
        return Err(std::io::Error::other("authentication failed"));
    }
    write_frame(stream, PY_WELCOME)
}

fn python_answer_challenge<S: Read + Write>(stream: &mut S, authkey: &[u8]) -> std::io::Result<()> {
    let challenge = read_frame(stream)?;
    let Some(message) = challenge.strip_prefix(PY_CHALLENGE) else {
        return Err(std::io::Error::other("expected challenge"));
    };
    if message.len() < 20 {
        return Err(std::io::Error::other("challenge too short"));
    }
    let mut response = b"{sha256}".to_vec();
    response.extend_from_slice(&hmac_sha256(authkey, message));
    write_frame(stream, &response)?;
    let welcome = read_frame(stream)?;
    if welcome != PY_WELCOME {
        return Err(std::io::Error::other("digest rejected"));
    }
    Ok(())
}

/// Python-wire-compatible JSON-RPC server.
///
/// Python clients connect with `multiprocessing.connection.Client(("127.0.0.1", port), authkey=...)`.
/// The handshake and 4-byte framing match CPython; payloads are pickles.
pub struct PythonRpcServer {
    listener: TcpListener,
    authkey: Vec<u8>,
    tokens: HashMap<String, String>,
    registry: Arc<RpcRegistry>,
}

impl PythonRpcServer {
    pub fn bind(
        address: &str,
        authkey: Vec<u8>,
        tokens: HashMap<String, String>,
        registry: RpcRegistry,
    ) -> std::io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(address)?,
            authkey,
            tokens,
            registry: Arc::new(registry),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Blocking accept loop; spawn a thread for each client.
    pub fn serve(self) {
        for connection in self.listener.incoming() {
            let Ok(stream) = connection else {
                break;
            };
            let authkey = self.authkey.clone();
            let tokens = self.tokens.clone();
            let registry = Arc::clone(&self.registry);
            thread::spawn(move || {
                let _ = handle_python_connection(stream, &authkey, tokens, registry);
            });
        }
    }
}

fn handle_python_connection<S: Read + Write>(
    mut stream: S,
    authkey: &[u8],
    tokens: HashMap<String, String>,
    registry: Arc<RpcRegistry>,
) -> std::io::Result<()> {
    python_deliver_challenge(&mut stream, authkey)?;
    python_answer_challenge(&mut stream, authkey)?;

    let hello = read_frame(&mut stream)?;
    let hello: Value = serde_pickle::from_slice(&hello, Default::default())
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    if hello.get("method").and_then(Value::as_str) != Some("hello") {
        let body = serde_pickle::to_vec(
            &json!({
                "jsonrpc": "2.0", "id": null,
                "error": {"code": UNAUTHORIZED, "message": "hello required"}
            }),
            Default::default(),
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        write_frame(&mut stream, &body)?;
        return Ok(());
    }
    let token = hello
        .get("params")
        .and_then(|params| params.get("token"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(role) = tokens.get(token) else {
        let body = serde_pickle::to_vec(
            &json!({
                "jsonrpc": "2.0", "id": hello.get("id").cloned().unwrap_or(Value::Null),
                "error": {"code": UNAUTHORIZED, "message": "bad token"}
            }),
            Default::default(),
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        write_frame(&mut stream, &body)?;
        return Ok(());
    };
    let response = json!({
        "jsonrpc": "2.0",
        "id": hello.get("id").cloned().unwrap_or(Value::Null),
        "result": {"role": role, "methods": registry.methods_for(role)}
    });
    write_frame(
        &mut stream,
        &serde_pickle::to_vec(&response, Default::default())
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    )?;

    while let Ok(frame) = read_frame(&mut stream) {
        let request: Value = match serde_pickle::from_slice(&frame, Default::default()) {
            Ok(request) => request,
            Err(_) => break,
        };
        let response = registry.dispatch(&request, role);
        let bytes = serde_pickle::to_vec(&response, Default::default())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        write_frame(&mut stream, &bytes)?;
    }
    Ok(())
}

/// Windows named-pipe variant: Python `Client(r"\\.\pipe\name", authkey=...)`.
#[cfg(windows)]
mod win_pipe {
    use super::MAX_MESSAGE;
    use std::io::{Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    pub struct PipeConn {
        handle: HANDLE,
    }

    impl PipeConn {
        pub fn from_handle(handle: HANDLE) -> Self {
            Self { handle }
        }
    }

    unsafe impl Send for PipeConn {}

    impl Read for PipeConn {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut read = 0u32;
            let ok = unsafe {
                ReadFile(
                    self.handle,
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as u32,
                    &mut read,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(read as usize)
        }
    }

    impl Write for PipeConn {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut written = 0u32;
            let ok = unsafe {
                WriteFile(
                    self.handle,
                    buf.as_ptr() as *const _,
                    buf.len() as u32,
                    &mut written,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(written as usize)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl PipeConn {
        pub fn read_message(&mut self) -> std::io::Result<Vec<u8>> {
            let mut buffer = vec![0u8; MAX_MESSAGE];
            let mut read = 0u32;
            let ok = unsafe {
                ReadFile(
                    self.handle,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len() as u32,
                    &mut read,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            buffer.truncate(read as usize);
            Ok(buffer)
        }

        pub fn write_message(&mut self, payload: &[u8]) -> std::io::Result<()> {
            if payload.len() > MAX_MESSAGE {
                return Err(std::io::Error::other("message too large"));
            }
            let mut written = 0u32;
            let ok = unsafe {
                WriteFile(
                    self.handle,
                    payload.as_ptr() as *const _,
                    payload.len() as u32,
                    &mut written,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for PipeConn {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }

    pub fn create_instance(pipe_name: &str) -> std::io::Result<PipeConn> {
        let wide: Vec<u16> = std::ffi::OsStr::new(pipe_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65_536,
                65_536,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        let ok = unsafe { ConnectNamedPipe(handle, null_mut()) };
        if ok == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                unsafe {
                    CloseHandle(handle);
                }
                return Err(error);
            }
        }
        Ok(PipeConn::from_handle(handle))
    }
}

#[cfg(windows)]
fn handle_python_pipe_connection(
    mut stream: win_pipe::PipeConn,
    authkey: Vec<u8>,
    tokens: HashMap<String, String>,
    registry: Arc<RpcRegistry>,
) -> std::io::Result<()> {
    let mut random = [0u8; 40];
    OsRng.fill_bytes(&mut random);
    let mut message = b"{sha256}".to_vec();
    message.extend_from_slice(&random);
    let mut challenge = PY_CHALLENGE.to_vec();
    challenge.extend_from_slice(&message);
    stream.write_message(&challenge)?;
    let response = stream.read_message()?;
    let mut expected = b"{sha256}".to_vec();
    expected.extend_from_slice(&hmac_sha256(&authkey, &message));
    if response != expected {
        let _ = stream.write_message(PY_FAILURE);
        return Err(std::io::Error::other("authentication failed"));
    }
    stream.write_message(PY_WELCOME)?;

    let client_challenge = stream.read_message()?;
    let Some(message) = client_challenge.strip_prefix(PY_CHALLENGE) else {
        return Err(std::io::Error::other("expected challenge"));
    };
    let mut response = b"{sha256}".to_vec();
    response.extend_from_slice(&hmac_sha256(&authkey, message));
    stream.write_message(&response)?;
    if stream.read_message()? != PY_WELCOME {
        return Err(std::io::Error::other("digest rejected"));
    }

    let hello: Value = serde_pickle::from_slice(&stream.read_message()?, Default::default())
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    if hello.get("method").and_then(Value::as_str) != Some("hello") {
        let body = serde_pickle::to_vec(
            &json!({
                "jsonrpc": "2.0", "id": null,
                "error": {"code": UNAUTHORIZED, "message": "hello required"}
            }),
            Default::default(),
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        stream.write_message(&body)?;
        return Ok(());
    }
    let token = hello
        .get("params")
        .and_then(|params| params.get("token"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(role) = tokens.get(token) else {
        let body = serde_pickle::to_vec(
            &json!({
                "jsonrpc": "2.0", "id": hello.get("id").cloned().unwrap_or(Value::Null),
                "error": {"code": UNAUTHORIZED, "message": "bad token"}
            }),
            Default::default(),
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        stream.write_message(&body)?;
        return Ok(());
    };
    let hello_response = json!({
        "jsonrpc": "2.0",
        "id": hello.get("id").cloned().unwrap_or(Value::Null),
        "result": {"role": role, "methods": registry.methods_for(role)}
    });
    stream.write_message(
        &serde_pickle::to_vec(&hello_response, Default::default())
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    )?;

    while let Ok(message) = stream.read_message() {
        let request: Value = match serde_pickle::from_slice(&message, Default::default()) {
            Ok(request) => request,
            Err(_) => break,
        };
        let response = registry.dispatch(&request, role);
        stream.write_message(
            &serde_pickle::to_vec(&response, Default::default())
                .map_err(|error| std::io::Error::other(error.to_string()))?,
        )?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn serve_python_pipe(
    pipe_name: &str,
    authkey: Vec<u8>,
    tokens: HashMap<String, String>,
    registry: RpcRegistry,
) -> std::io::Result<()> {
    let registry = Arc::new(registry);
    loop {
        let stream = win_pipe::create_instance(pipe_name)?;
        let authkey = authkey.clone();
        let tokens = tokens.clone();
        let registry = Arc::clone(&registry);
        thread::spawn(move || {
            let _ = handle_python_pipe_connection(stream, authkey, tokens, registry);
        });
    }
}

/// Unix-domain variant: Python `Client(path, authkey=...)`.
#[cfg(unix)]
pub struct PythonUnixRpcServer {
    path: std::path::PathBuf,
    listener: std::os::unix::net::UnixListener,
    authkey: Vec<u8>,
    tokens: HashMap<String, String>,
    registry: Arc<RpcRegistry>,
}

#[cfg(unix)]
impl PythonUnixRpcServer {
    pub fn bind(
        path: &str,
        authkey: Vec<u8>,
        tokens: HashMap<String, String>,
        registry: RpcRegistry,
    ) -> std::io::Result<Self> {
        let path = std::path::PathBuf::from(path);
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        Ok(Self {
            path,
            listener,
            authkey,
            tokens,
            registry: Arc::new(registry),
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn serve(self) {
        for connection in self.listener.incoming() {
            let Ok(stream) = connection else {
                break;
            };
            let authkey = self.authkey.clone();
            let tokens = self.tokens.clone();
            let registry = Arc::clone(&self.registry);
            thread::spawn(move || {
                let _ = handle_python_connection(stream, &authkey, tokens, registry);
            });
        }
    }
}
