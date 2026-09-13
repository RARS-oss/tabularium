//! Lightweight HTTP transport (the `http` feature) as an alternative to `run_stdio`'s single
//! local process, for networked multi-agent use. Implements a scoped subset of MCP's "Streamable
//! HTTP" transport: a single `POST /mcp` endpoint carries JSON-RPC request/notification bodies,
//! sessions are tracked by an `Mcp-Session-Id` header established at `initialize`, and a
//! notification that produces a server-initiated message (today, only a `roots/list` re-ask) is
//! delivered as a one-shot `text/event-stream` response to that same POST rather than over a
//! standing GET stream -- nothing here generates messages outside of direct request handling, so
//! a persistent GET SSE channel would add real complexity for no present use. `GET /mcp` therefore
//! answers 405, which is spec-legal for a server that doesn't support server-initiated streams.
//!
//! ## Trust boundary
//! stdio's trust model is implicit: whoever can start the local process already has your
//! filesystem access. HTTP has none of that for free, so every request here requires a bearer
//! token (`Authorization: Bearer <token>`, compared in constant time) and the server binds to
//! loopback (`127.0.0.1`) unless the caller explicitly asks for something else -- binding wider
//! prints a loud warning, not a silent success. There is no TLS in this transport: it is meant for
//! local demos and machines you already trust on their own network, not an internet-facing
//! service. Put a real reverse proxy in front of it for that; this is deliberately not trying to
//! be one.
//!
//! ## Session model
//! Each session gets its own `Vault::open` via the caller-supplied [`VaultFactory`], exactly
//! mirroring "one stdio process per MCP client" today, just multiplexed over HTTP connections
//! within one OS process instead of one process per client. SQLite's WAL journal mode and
//! `busy_timeout` (already configured in `Vault::open`) are what make concurrent sessions against
//! the same vault file safe -- this transport adds no new concurrency mechanism of its own.

use crate::McpServer;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use tabularium_core::{Error, Result, Vault};
use tiny_http::{Header, Method, Request, Response, ResponseBox, Server};

/// Number of worker threads polling the listener for requests. Fixed rather than configurable:
/// this transport is scoped to local/demo multi-agent use, not a tuned production listener.
const WORKER_THREADS: usize = 8;

/// Opens (or reports failure to open) the vault for one new session. Called once per session, at
/// the `initialize` request that doesn't carry an existing `Mcp-Session-Id`. The vault itself must
/// already exist -- creating it on first use is the caller's job, done once before [`run_http`]
/// starts, exactly like the stdio `Serve` path does today.
pub type VaultFactory = Box<dyn Fn() -> std::result::Result<Vault, String> + Send + Sync>;

pub struct HttpConfig {
    pub bind: SocketAddr,
    pub token: String,
    pub log: bool,
}

/// 32 random bytes, hex-encoded -- used for both the bearer token and session ids. Not a
/// cryptographic identity like `VaultKeys`, just an unguessable string.
fn random_hex(n_bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; n_bytes];
    getrandom::fill(&mut buf).map_err(|e| Error::Crypto(format!("rng: {e}")))?;
    Ok(hex::encode(buf))
}

/// A fresh bearer token, suitable for [`HttpConfig::token`].
pub fn generate_token() -> Result<String> {
    random_hex(32)
}

/// Equal-time comparison so a wrong guess can't be narrowed down byte-by-byte from response
/// latency. Overkill for a local demo tool, cheap enough to just do right.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn header_value<'a>(req: &'a Request, name: &'static str) -> Option<&'a str> {
    req.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str())
}

fn json_response(status: u16, body: &Value) -> ResponseBox {
    Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap())
        .boxed()
}

/// A one-shot SSE frame: one `data:` event, then the response ends. Not a standing stream -- see
/// the module doc for why that's out of scope today.
fn sse_response(body: &Value) -> ResponseBox {
    Response::from_string(format!("data: {body}\n\n"))
        .with_status_code(200)
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap())
        .boxed()
}

fn empty_response(status: u16) -> ResponseBox {
    Response::empty(status).boxed()
}

fn plain_error(status: u16, message: &str) -> ResponseBox {
    Response::from_string(message.to_string()).with_status_code(status).boxed()
}

type SessionMap = RwLock<HashMap<String, Arc<Mutex<McpServer>>>>;

struct Shared {
    token: String,
    sessions: SessionMap,
    new_vault: VaultFactory,
    log: bool,
}

/// Serve MCP over HTTP until the process is killed.
pub fn run_http(config: HttpConfig, new_vault: VaultFactory) -> std::io::Result<()> {
    let server = Server::http(config.bind).map_err(std::io::Error::other)?;
    serve(server, config, new_vault)
}

/// Lower-level entry point for an already-bound listener -- lets a caller (tests, mainly) bind to
/// an ephemeral port via `tiny_http::Server::http("127.0.0.1:0")` and read the real port back from
/// `Server::server_addr()` before serving.
pub fn serve(server: Server, config: HttpConfig, new_vault: VaultFactory) -> std::io::Result<()> {
    let loopback = config.bind.ip().is_loopback();
    eprintln!("[tabularium-mcp] http listening on {}", server.server_addr());
    if !loopback {
        eprintln!(
            "[tabularium-mcp] WARNING: binding {} is not loopback -- this exposes the vault to \
             whoever can reach it on the network, and there is no TLS here: the bearer token \
             travels in plaintext. Put this behind a reverse proxy you control, or bind to \
             127.0.0.1 instead.",
            config.bind
        );
    }
    let shared = Arc::new(Shared { token: config.token, sessions: RwLock::new(HashMap::new()), new_vault, log: config.log });
    let server = Arc::new(server);
    let handles: Vec<_> = (0..WORKER_THREADS)
        .map(|_| {
            let server = Arc::clone(&server);
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || worker_loop(&server, &shared))
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

fn worker_loop(server: &Server, shared: &Arc<Shared>) {
    loop {
        match server.recv() {
            Ok(request) => handle_request(request, shared),
            Err(e) => eprintln!("[tabularium-mcp] http accept error: {e}"),
        }
    }
}

fn handle_request(request: Request, shared: &Arc<Shared>) {
    let path = request.url().split('?').next().unwrap_or("/").to_string();
    if path != "/mcp" {
        let _ = request.respond(plain_error(404, "not found; the MCP endpoint is /mcp"));
        return;
    }

    let auth_ok = header_value(&request, "Authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| constant_time_eq(t, &shared.token))
        .unwrap_or(false);
    if !auth_ok {
        let resp = Response::from_string("unauthorized")
            .with_status_code(401)
            .with_header(Header::from_bytes(&b"WWW-Authenticate"[..], &b"Bearer"[..]).unwrap())
            .boxed();
        let _ = request.respond(resp);
        return;
    }

    match request.method().clone() {
        Method::Post => handle_post(request, shared),
        Method::Delete => handle_delete(request, shared),
        // GET (a standing server-push stream) and anything else: 405, spec-legal for a server
        // that doesn't support server-initiated streams. See the module doc.
        _ => {
            let resp = Response::empty(405).with_header(Header::from_bytes(&b"Allow"[..], &b"POST, DELETE"[..]).unwrap()).boxed();
            let _ = request.respond(resp);
        }
    }
}

fn handle_delete(request: Request, shared: &Arc<Shared>) {
    let removed = header_value(&request, "Mcp-Session-Id").map(|id| shared.sessions.write().unwrap().remove(id).is_some()).unwrap_or(false);
    let status = if removed { 204 } else { 404 };
    let _ = request.respond(empty_response(status));
}

fn handle_post(mut request: Request, shared: &Arc<Shared>) {
    let mut body = String::new();
    if let Err(e) = request.as_reader().read_to_string(&mut body) {
        let _ = request.respond(plain_error(400, &format!("failed to read body: {e}")));
        return;
    }

    let msg: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            let err = json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": format!("parse error: {e}")}});
            let _ = request.respond(json_response(200, &err));
            return;
        }
    };

    let is_notification = msg.get("id").filter(|v| !v.is_null()).is_none();
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let existing_session_id = header_value(&request, "Mcp-Session-Id").map(|s| s.to_string());

    let (session_id, server_arc, is_new_session) = match existing_session_id {
        Some(id) => match shared.sessions.read().unwrap().get(&id).cloned() {
            Some(s) => (id, s, false),
            None => {
                let _ = request.respond(plain_error(404, "unknown Mcp-Session-Id; call initialize again"));
                return;
            }
        },
        None => {
            if method != "initialize" {
                let _ = request.respond(plain_error(400, "Mcp-Session-Id header required (call initialize first)"));
                return;
            }
            let vault = match (shared.new_vault)() {
                Ok(v) => v,
                Err(e) => {
                    let _ = request.respond(plain_error(500, &format!("failed to open vault: {e}")));
                    return;
                }
            };
            let id = match random_hex(16) {
                Ok(id) => id,
                Err(e) => {
                    let _ = request.respond(plain_error(500, &format!("{e}")));
                    return;
                }
            };
            let server = Arc::new(Mutex::new(McpServer::new(vault)));
            shared.sessions.write().unwrap().insert(id.clone(), Arc::clone(&server));
            (id, server, true)
        }
    };

    if shared.log {
        eprintln!("[tabularium-mcp] http <- {method} (session {session_id})");
    }

    let result = server_arc.lock().unwrap().handle_message(msg);

    let mut response = match (is_notification, result) {
        (false, Some(v)) => json_response(200, &v),
        (false, None) => json_response(
            200,
            &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32603, "message": "internal error: no response produced for a request"}}),
        ),
        (true, Some(v)) => sse_response(&v),
        (true, None) => empty_response(202),
    };
    if is_new_session {
        response.add_header(Header::from_bytes(&b"Mcp-Session-Id"[..], session_id.as_bytes()).unwrap());
    }
    let _ = request.respond(response);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tabularium_core::Vault;
    use ureq::config::Config;
    use ureq::Agent;

    const TOKEN: &str = "test-token";

    /// Starts a real server on an ephemeral loopback port, backed by a fresh scratch vault, and
    /// returns its base URL and an `Agent` configured to treat every status code as a normal
    /// response (so a test can assert on 401/404/405 without matching on `Err`).
    fn start() -> (String, Agent, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let vault_dir = dir.path().join("v");
        Vault::init(&vault_dir, "t", Some(dir.path())).unwrap();
        let factory: VaultFactory = Box::new(move || {
            let mut v = Vault::open(&vault_dir).map_err(|e| e.to_string())?;
            v.set_embedder(None);
            Ok(v)
        });
        let server = Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        let config = HttpConfig { bind: addr, token: TOKEN.to_string(), log: false };
        std::thread::spawn(move || {
            let _ = serve(server, config, factory);
        });
        let agent: Agent = Config::builder().http_status_as_error(false).build().into();
        (format!("http://{addr}/mcp"), agent, dir)
    }

    fn init_request() -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}})
    }

    #[test]
    fn rejects_missing_or_wrong_bearer_token() {
        let (url, agent, _dir) = start();
        let r = agent.post(&url).send(init_request().to_string()).unwrap();
        assert_eq!(r.status().as_u16(), 401, "no Authorization header at all");

        let r = agent.post(&url).header("Authorization", "Bearer nope").send(init_request().to_string()).unwrap();
        assert_eq!(r.status().as_u16(), 401, "wrong token");
    }

    #[test]
    fn initialize_without_session_id_starts_one_and_tool_calls_round_trip() {
        let (url, agent, _dir) = start();
        let mut r = agent.post(&url).header("Authorization", format!("Bearer {TOKEN}")).send(init_request().to_string()).unwrap();
        assert_eq!(r.status().as_u16(), 200);
        let session_id = r.headers().get("Mcp-Session-Id").expect("initialize response carries a session id").to_str().unwrap().to_string();
        let body: Value = serde_json::from_str(&r.body_mut().read_to_string().unwrap()).unwrap();
        assert_eq!(body["result"]["serverInfo"]["name"], crate::SERVER_NAME);

        // notifications/initialized with no roots capability: nothing to send back -> 202, empty.
        let notif = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let r = agent
            .post(&url)
            .header("Authorization", format!("Bearer {TOKEN}"))
            .header("Mcp-Session-Id", &session_id)
            .send(notif.to_string())
            .unwrap();
        assert_eq!(r.status().as_u16(), 202);

        // A real tool call over the now-established session.
        let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": {"name": "memory_observe", "arguments": {"kind": "utterance", "content": "hello over http"}}});
        let mut r = agent
            .post(&url)
            .header("Authorization", format!("Bearer {TOKEN}"))
            .header("Mcp-Session-Id", &session_id)
            .send(call.to_string())
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        let body: Value = serde_json::from_str(&r.body_mut().read_to_string().unwrap()).unwrap();
        assert_eq!(body["result"]["isError"], false, "{body}");
        assert!(body["result"]["structuredContent"]["event_id"].is_string());
    }

    #[test]
    fn unknown_or_missing_session_id_is_rejected() {
        let (url, agent, _dir) = start();
        let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});

        let r = agent.post(&url).header("Authorization", format!("Bearer {TOKEN}")).send(call.to_string()).unwrap();
        assert_eq!(r.status().as_u16(), 400, "no session id and not an initialize call");

        let r = agent
            .post(&url)
            .header("Authorization", format!("Bearer {TOKEN}"))
            .header("Mcp-Session-Id", "does-not-exist")
            .send(call.to_string())
            .unwrap();
        assert_eq!(r.status().as_u16(), 404, "unknown session id");
    }

    #[test]
    fn roots_capable_initialize_delivers_the_reask_as_one_shot_sse() {
        let (url, agent, _dir) = start();
        let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2025-06-18", "capabilities": {"roots": {}}, "clientInfo": {"name": "test", "version": "1"}}});
        let r = agent.post(&url).header("Authorization", format!("Bearer {TOKEN}")).send(init.to_string()).unwrap();
        let session_id = r.headers().get("Mcp-Session-Id").unwrap().to_str().unwrap().to_string();

        let notif = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let mut r = agent
            .post(&url)
            .header("Authorization", format!("Bearer {TOKEN}"))
            .header("Mcp-Session-Id", &session_id)
            .send(notif.to_string())
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert_eq!(r.headers().get("Content-Type").unwrap().to_str().unwrap(), "text/event-stream");
        let text = r.body_mut().read_to_string().unwrap();
        assert!(text.starts_with("data: "), "{text}");
        let payload: Value = serde_json::from_str(text.trim_start_matches("data: ").trim()).unwrap();
        assert_eq!(payload["method"], "roots/list");
    }

    #[test]
    fn delete_ends_a_session() {
        let (url, agent, _dir) = start();
        let r = agent.post(&url).header("Authorization", format!("Bearer {TOKEN}")).send(init_request().to_string()).unwrap();
        let session_id = r.headers().get("Mcp-Session-Id").unwrap().to_str().unwrap().to_string();

        let r = agent.delete(&url).header("Authorization", format!("Bearer {TOKEN}")).header("Mcp-Session-Id", &session_id).call().unwrap();
        assert_eq!(r.status().as_u16(), 204);

        let r = agent.delete(&url).header("Authorization", format!("Bearer {TOKEN}")).header("Mcp-Session-Id", &session_id).call().unwrap();
        assert_eq!(r.status().as_u16(), 404, "deleting an already-gone session");

        let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
        let r = agent
            .post(&url)
            .header("Authorization", format!("Bearer {TOKEN}"))
            .header("Mcp-Session-Id", &session_id)
            .send(call.to_string())
            .unwrap();
        assert_eq!(r.status().as_u16(), 404, "the deleted session no longer exists");
    }

    #[test]
    fn unknown_path_is_404_and_get_is_405() {
        let (url, agent, _dir) = start();
        let base = url.trim_end_matches("/mcp");
        let r = agent.get(format!("{base}/nope")).header("Authorization", format!("Bearer {TOKEN}")).call().unwrap();
        assert_eq!(r.status().as_u16(), 404);

        let r = agent.get(&url).header("Authorization", format!("Bearer {TOKEN}")).call().unwrap();
        assert_eq!(r.status().as_u16(), 405);
    }

    #[test]
    fn malformed_json_body_is_a_json_rpc_parse_error_not_an_http_error() {
        let (url, agent, _dir) = start();
        let mut r = agent.post(&url).header("Authorization", format!("Bearer {TOKEN}")).send("{not json").unwrap();
        assert_eq!(r.status().as_u16(), 200, "parse errors are JSON-RPC-level, not HTTP-level");
        let body: Value = serde_json::from_str(&r.body_mut().read_to_string().unwrap()).unwrap();
        assert_eq!(body["error"]["code"], -32700);
    }
}
