use anyhow::{Context, Result, anyhow, bail};
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{SecondsFormat, Utc};
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::thread;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::models::{AgentSkillSpec, GatewayTelemetry};

#[derive(Debug, Clone)]
pub struct GatewayStartAgent {
    pub name: String,
    pub serve: bool,
    pub description: Option<String>,
    pub skills: Vec<AgentSkillSpec>,
    pub streaming: bool,
    pub socket_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct GatewayStartOptions {
    pub run_id: String,
    pub socket_path: PathBuf,
    pub log_path: PathBuf,
    pub bind_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub stream_idle_timeout_ms: u64,
    pub max_payload_bytes: usize,
    pub token_by_agent: HashMap<String, String>,
    pub agents: Vec<GatewayStartAgent>,
}

#[derive(Default)]
struct GatewayStats {
    requests_total: AtomicU64,
    auth_failures: AtomicU64,
    proxy_errors: AtomicU64,
    active_stream_sessions: AtomicU64,
    stream_sessions_peak: AtomicU64,
}

impl GatewayStats {
    fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.requests_total.load(Ordering::Relaxed),
            self.auth_failures.load(Ordering::Relaxed),
            self.proxy_errors.load(Ordering::Relaxed),
            self.stream_sessions_peak.load(Ordering::Relaxed),
        )
    }

    fn open_stream(self: &Arc<Self>) -> StreamSessionGuard {
        let active = self
            .active_stream_sessions
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let mut peak = self.stream_sessions_peak.load(Ordering::Relaxed);
        while active > peak {
            match self.stream_sessions_peak.compare_exchange_weak(
                peak,
                active,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => peak = current,
            }
        }
        StreamSessionGuard {
            stats: Arc::clone(self),
        }
    }
}

struct StreamSessionGuard {
    stats: Arc<GatewayStats>,
}

impl Drop for StreamSessionGuard {
    fn drop(&mut self) {
        self.stats
            .active_stream_sessions
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct AgentRouteState {
    serve: bool,
    description: Option<String>,
    skills: Vec<AgentSkillSpec>,
    streaming: bool,
    socket_path: PathBuf,
}

#[derive(Clone)]
struct GatewayState {
    run_id: String,
    request_timeout_ms: u64,
    stream_idle_timeout_ms: u64,
    max_payload_bytes: usize,
    agents: Arc<HashMap<String, AgentRouteState>>,
    token_to_agent: Arc<HashMap<String, String>>,
    stats: Arc<GatewayStats>,
    log_file: Arc<Mutex<fs::File>>,
}

pub struct GatewayHandle {
    socket_path: PathBuf,
    started_at: String,
    stats: Arc<GatewayStats>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<thread::JoinHandle<Result<()>>>,
}

impl GatewayHandle {
    pub fn stop(&mut self) -> Result<GatewayTelemetry> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        if let Some(handle) = self.join_handle.take() {
            match handle.join() {
                Ok(join_result) => join_result?,
                Err(_) => bail!("gateway thread panicked"),
            }
        }

        let stopped_at = now_iso();
        let (requests_total, auth_failures, proxy_errors, stream_sessions_peak) =
            self.stats.snapshot();

        let _ = fs::remove_file(&self.socket_path);

        Ok(GatewayTelemetry {
            enabled: true,
            transport: "uds".to_string(),
            socket_path: self.socket_path.to_string_lossy().to_string(),
            started_at: self.started_at.clone(),
            stopped_at,
            requests_total,
            auth_failures,
            proxy_errors,
            stream_sessions_peak,
        })
    }

    pub fn startup_telemetry(&self) -> GatewayTelemetry {
        GatewayTelemetry {
            enabled: true,
            transport: "uds".to_string(),
            socket_path: self.socket_path.to_string_lossy().to_string(),
            started_at: self.started_at.clone(),
            stopped_at: "".to_string(),
            requests_total: 0,
            auth_failures: 0,
            proxy_errors: 0,
            stream_sessions_peak: 0,
        }
    }
}

pub fn start_gateway(opts: GatewayStartOptions) -> Result<GatewayHandle> {
    let parent = opts
        .socket_path
        .parent()
        .ok_or_else(|| anyhow!("gateway socket path must have a parent"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create gateway dir {}", parent.display()))?;
    if opts.socket_path.exists() {
        fs::remove_file(&opts.socket_path)
            .with_context(|| format!("failed to remove {}", opts.socket_path.display()))?;
    }

    if let Some(log_parent) = opts.log_path.parent() {
        fs::create_dir_all(log_parent)
            .with_context(|| format!("failed to create {}", log_parent.display()))?;
    }
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&opts.log_path)
        .with_context(|| format!("failed to open {}", opts.log_path.display()))?;

    let started_at = now_iso();
    let stats = Arc::new(GatewayStats::default());
    let log_file = Arc::new(Mutex::new(log_file));

    let mut agents = HashMap::new();
    for agent in opts.agents {
        agents.insert(
            agent.name.clone(),
            AgentRouteState {
                serve: agent.serve,
                description: agent.description,
                skills: agent.skills,
                streaming: agent.streaming,
                socket_path: agent.socket_path,
            },
        );
    }
    let token_to_agent: HashMap<String, String> = opts
        .token_by_agent
        .iter()
        .map(|(agent, token)| (token.clone(), agent.clone()))
        .collect();

    let state = GatewayState {
        run_id: opts.run_id.clone(),
        request_timeout_ms: opts.request_timeout_ms,
        stream_idle_timeout_ms: opts.stream_idle_timeout_ms,
        max_payload_bytes: opts.max_payload_bytes,
        agents: Arc::new(agents),
        token_to_agent: Arc::new(token_to_agent),
        stats: Arc::clone(&stats),
        log_file: Arc::clone(&log_file),
    };

    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let socket_path = opts.socket_path.clone();
    let bind_timeout = Duration::from_millis(opts.bind_timeout_ms);

    let join_handle = thread::spawn(move || -> Result<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build gateway runtime")?;

        rt.block_on(async move {
            let listener = match UnixListener::bind(&socket_path) {
                Ok(listener) => listener,
                Err(err) => {
                    let _ = ready_tx.send(Err(format!(
                        "failed to bind gateway socket {}: {err}",
                        socket_path.display()
                    )));
                    return Err(err).context("failed to bind gateway socket");
                }
            };

            log_line(
                &state.log_file,
                &format!(
                    "gateway start run_id={} socket={} stream_idle_timeout_ms={}",
                    state.run_id,
                    socket_path.display(),
                    state.stream_idle_timeout_ms
                ),
            );

            let app = build_router(state.clone());
            let _ = ready_tx.send(Ok(()));

            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .context("gateway server failed")?;

            log_line(
                &state.log_file,
                &format!(
                    "gateway stop run_id={} socket={}",
                    state.run_id,
                    socket_path.display()
                ),
            );
            Ok(())
        })
    });

    match ready_rx.recv_timeout(bind_timeout) {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            let _ = join_handle.join();
            bail!("{err}");
        }
        Err(RecvTimeoutError::Timeout) => {
            let _ = shutdown_tx.send(());
            let _ = join_handle.join();
            bail!("timed out waiting for gateway bind");
        }
        Err(RecvTimeoutError::Disconnected) => {
            let _ = join_handle.join();
            bail!("gateway failed before signaling readiness");
        }
    }

    Ok(GatewayHandle {
        socket_path: opts.socket_path,
        started_at,
        stats,
        shutdown_tx: Some(shutdown_tx),
        join_handle: Some(join_handle),
    })
}

fn build_router(state: GatewayState) -> Router {
    Router::new()
        .without_v07_checks()
        .route("/.well-known/agent-card.json", get(get_gateway_card))
        .route(
            "/v1/agents/{agent}/.well-known/agent-card.json",
            get(get_agent_card),
        )
        .route("/v1/agents/{agent}/message:send", post(proxy_message_send))
        .route(
            "/v1/agents/{agent}/message:stream",
            post(proxy_message_stream),
        )
        .route(
            "/v1/agents/{agent}/tasks/{task_id}",
            get(proxy_task_get).post(proxy_task_cancel),
        )
        .with_state(state)
}

async fn get_gateway_card(State(state): State<GatewayState>) -> Json<serde_json::Value> {
    let agents = state
        .agents
        .iter()
        .filter(|(_, cfg)| cfg.serve)
        .map(|(name, cfg)| {
            serde_json::json!({
                "name": name,
                "base_url": format!("http://a2a.local/v1/agents/{name}"),
                "card_url": format!("http://a2a.local/v1/agents/{name}/.well-known/agent-card.json"),
                "streaming": cfg.streaming,
            })
        })
        .collect::<Vec<_>>();
    Json(serde_json::json!({
        "name": "normies-host-gateway",
        "description": "Per-run local A2A gateway for normies agents",
        "run_id": state.run_id,
        "transport": "uds",
        "agents": agents
    }))
}

async fn get_agent_card(
    State(state): State<GatewayState>,
    Path(agent): Path<String>,
) -> std::result::Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(cfg) = state.agents.get(&agent) else {
        return Err(error_json(StatusCode::NOT_FOUND, "agent not found"));
    };
    if !cfg.serve {
        return Err(error_json(
            StatusCode::CONFLICT,
            "target agent is not A2A-serving",
        ));
    }

    Ok(Json(serde_json::json!({
        "name": agent,
        "description": cfg.description.clone().unwrap_or_else(|| "normies agent".to_string()),
        "base_url": format!("http://a2a.local/v1/agents/{}", cfg_name(&agent)),
        "streaming": cfg.streaming,
        "skills": cfg.skills,
    })))
}

async fn proxy_message_send(
    State(state): State<GatewayState>,
    Path(agent): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Response, (StatusCode, Json<serde_json::Value>)> {
    proxy_to_agent(
        state,
        agent,
        "/message:send".to_string(),
        Method::POST,
        headers,
        body,
        false,
    )
    .await
}

async fn proxy_message_stream(
    State(state): State<GatewayState>,
    Path(agent): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Response, (StatusCode, Json<serde_json::Value>)> {
    proxy_to_agent(
        state,
        agent,
        "/message:stream".to_string(),
        Method::POST,
        headers,
        body,
        true,
    )
    .await
}

async fn proxy_task_get(
    State(state): State<GatewayState>,
    Path((agent, task_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> std::result::Result<Response, (StatusCode, Json<serde_json::Value>)> {
    proxy_to_agent(
        state,
        agent,
        format!("/tasks/{task_id}"),
        Method::GET,
        headers,
        Bytes::new(),
        false,
    )
    .await
}

async fn proxy_task_cancel(
    State(state): State<GatewayState>,
    Path((agent, task_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Response, (StatusCode, Json<serde_json::Value>)> {
    if !task_id.ends_with(":cancel") {
        return Err(error_json(
            StatusCode::NOT_FOUND,
            "unsupported task endpoint",
        ));
    }
    proxy_to_agent(
        state,
        agent,
        format!("/tasks/{task_id}:cancel"),
        Method::POST,
        headers,
        body,
        false,
    )
    .await
}

async fn proxy_to_agent(
    state: GatewayState,
    target_agent: String,
    target_path: String,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    stream_response: bool,
) -> std::result::Result<Response, (StatusCode, Json<serde_json::Value>)> {
    state.stats.requests_total.fetch_add(1, Ordering::Relaxed);

    if body.len() > state.max_payload_bytes {
        return Err(error_json(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds a2a_gateway.max_payload_bytes",
        ));
    }

    let caller_agent = authenticate_agent(&state, &headers)?;
    if let Some(claimed) = headers.get("x-normies-caller-agent")
        && claimed.to_str().ok() != Some(caller_agent.as_str())
    {
        return Err(error_json(
            StatusCode::FORBIDDEN,
            "caller-agent header does not match token identity",
        ));
    }

    let Some(target_cfg) = state.agents.get(&target_agent).cloned() else {
        return Err(error_json(StatusCode::NOT_FOUND, "target agent not found"));
    };
    if !target_cfg.serve {
        return Err(error_json(
            StatusCode::CONFLICT,
            "target agent is not A2A-serving",
        ));
    }

    let connector = UdsConnector::new(target_cfg.socket_path.clone());
    let client: Client<UdsConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let uri = build_local_uri(&target_path)
        .map_err(|_| error_json(StatusCode::INTERNAL_SERVER_ERROR, "invalid upstream uri"))?;
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Full::new(body))
        .map_err(|_| {
            error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid upstream request",
            )
        })?;
    copy_proxy_headers(request.headers_mut(), &headers);
    insert_header(
        request.headers_mut(),
        "x-normies-run-id",
        &state.run_id,
        StatusCode::INTERNAL_SERVER_ERROR,
    )?;
    insert_header(
        request.headers_mut(),
        "x-normies-caller-agent",
        &caller_agent,
        StatusCode::FORBIDDEN,
    )?;
    insert_header(
        request.headers_mut(),
        "x-normies-target-agent",
        &target_agent,
        StatusCode::INTERNAL_SERVER_ERROR,
    )?;

    let request_timeout = Duration::from_millis(state.request_timeout_ms);
    let upstream = timeout(request_timeout, client.request(request))
        .await
        .map_err(|_| {
            state.stats.proxy_errors.fetch_add(1, Ordering::Relaxed);
            error_json(StatusCode::GATEWAY_TIMEOUT, "upstream request timed out")
        })?
        .map_err(|err| {
            state.stats.proxy_errors.fetch_add(1, Ordering::Relaxed);
            log_line(
                &state.log_file,
                &format!(
                    "proxy error run_id={} caller={} target={} path={} err={}",
                    state.run_id, caller_agent, target_agent, target_path, err
                ),
            );
            error_json(StatusCode::BAD_GATEWAY, "upstream request failed")
        })?;

    log_line(
        &state.log_file,
        &format!(
            "proxy ok run_id={} caller={} target={} path={}",
            state.run_id, caller_agent, target_agent, target_path
        ),
    );
    Ok(build_proxy_response(
        upstream,
        if stream_response {
            Some(Arc::clone(&state.stats))
        } else {
            None
        },
    ))
}

fn build_proxy_response(
    resp: hyper::Response<Incoming>,
    stats: Option<Arc<GatewayStats>>,
) -> Response {
    let (parts, body) = resp.into_parts();
    let guard = stats.map(|s| s.open_stream());
    let stream = body.into_data_stream().inspect(move |_| {
        let _ = &guard;
    });
    Response::from_parts(parts, Body::from_stream(stream))
}

fn copy_proxy_headers(dst: &mut HeaderMap, src: &HeaderMap) {
    if let Some(content_type) = src.get(CONTENT_TYPE) {
        dst.insert(CONTENT_TYPE, content_type.clone());
    }
    if let Some(accept) = src.get(ACCEPT) {
        dst.insert(ACCEPT, accept.clone());
    }
}

fn insert_header(
    headers: &mut HeaderMap,
    key: &'static str,
    value: &str,
    code: StatusCode,
) -> std::result::Result<(), (StatusCode, Json<serde_json::Value>)> {
    let value = HeaderValue::from_str(value)
        .map_err(|_| error_json(code, "invalid tracing header value"))?;
    headers.insert(key, value);
    Ok(())
}

fn authenticate_agent(
    state: &GatewayState,
    headers: &HeaderMap,
) -> std::result::Result<String, (StatusCode, Json<serde_json::Value>)> {
    let Some(raw_auth) = headers.get(AUTHORIZATION) else {
        state.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
        return Err(error_json(
            StatusCode::UNAUTHORIZED,
            "missing authorization",
        ));
    };
    let Ok(raw_auth) = raw_auth.to_str() else {
        state.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
        return Err(error_json(
            StatusCode::UNAUTHORIZED,
            "invalid authorization",
        ));
    };
    let Some(token) = raw_auth.strip_prefix("Bearer ") else {
        state.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
        return Err(error_json(
            StatusCode::UNAUTHORIZED,
            "authorization must use Bearer token",
        ));
    };

    let Some(agent) = state.token_to_agent.get(token) else {
        state.stats.auth_failures.fetch_add(1, Ordering::Relaxed);
        return Err(error_json(StatusCode::UNAUTHORIZED, "unknown bearer token"));
    };
    Ok(agent.clone())
}

fn build_local_uri(path: &str) -> Result<Uri> {
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Uri::builder()
        .scheme("http")
        .authority("a2a.local")
        .path_and_query(path.as_str())
        .build()
        .context("invalid uri")
}

fn error_json(code: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        code,
        Json(serde_json::json!({
            "error": message
        })),
    )
}

fn log_line(file: &Arc<Mutex<fs::File>>, message: &str) {
    let now = now_iso();
    let mut guard = match file.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    use std::io::Write as _;
    let _ = writeln!(guard, "{} {}", now, message);
}

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn cfg_name(agent: &str) -> String {
    agent.to_string()
}

#[derive(Clone)]
struct UdsConnector {
    socket_path: Arc<PathBuf>,
}

impl UdsConnector {
    fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path: Arc::new(socket_path),
        }
    }
}

impl tower_service::Service<Uri> for UdsConnector {
    type Response = TokioIo<UnixStream>;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Uri) -> Self::Future {
        let socket_path = Arc::clone(&self.socket_path);
        Box::pin(async move {
            let stream = UnixStream::connect(socket_path.as_ref()).await?;
            Ok(TokioIo::new(stream))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use axum::extract::Request;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{Router, body::Bytes};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn missing_auth_is_unauthorized() -> Result<()> {
        let state = GatewayState {
            run_id: "r1".to_string(),
            request_timeout_ms: 1000,
            stream_idle_timeout_ms: 1000,
            max_payload_bytes: 1024,
            agents: Arc::new(HashMap::new()),
            token_to_agent: Arc::new(HashMap::new()),
            stats: Arc::new(GatewayStats::default()),
            log_file: Arc::new(Mutex::new(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open("/tmp/normies-gateway-test.log")?,
            )),
        };
        let headers = HeaderMap::new();
        let err = authenticate_agent(&state, &headers).expect_err("expected unauthorized");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn proxies_message_send_to_target_socket() -> Result<()> {
        let tmp = TempDir::new()?;
        let target_socket = tmp.path().join("target.sock");
        let gateway_socket = tmp.path().join("gateway.sock");
        let gateway_log = tmp.path().join("gateway.log");

        let (upstream_shutdown_tx, upstream_shutdown_rx) = oneshot::channel::<()>();
        let target_socket_clone = target_socket.clone();
        tokio::spawn(async move {
            let _ = fs::remove_file(&target_socket_clone);
            let listener = UnixListener::bind(&target_socket_clone).expect("bind target");
            let app = Router::new().without_v07_checks().route(
                "/message:send",
                post(|headers: HeaderMap, body: Bytes| async move {
                    let caller = headers
                        .get("x-normies-caller-agent")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("missing");
                    Json(serde_json::json!({
                        "caller": caller,
                        "body": String::from_utf8_lossy(&body)
                    }))
                }),
            );
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = upstream_shutdown_rx.await;
                })
                .await
                .expect("upstream server");
        });

        let mut handle = start_gateway(GatewayStartOptions {
            run_id: "run-gateway-test".to_string(),
            socket_path: gateway_socket.clone(),
            log_path: gateway_log,
            bind_timeout_ms: 2000,
            request_timeout_ms: 2000,
            stream_idle_timeout_ms: 5000,
            max_payload_bytes: 1024 * 1024,
            token_by_agent: HashMap::from([("a".to_string(), "tok-a".to_string())]),
            agents: vec![
                GatewayStartAgent {
                    name: "a".to_string(),
                    serve: false,
                    description: None,
                    skills: vec![],
                    streaming: false,
                    socket_path: tmp.path().join("a.sock"),
                },
                GatewayStartAgent {
                    name: "b".to_string(),
                    serve: true,
                    description: Some("b".to_string()),
                    skills: vec![],
                    streaming: true,
                    socket_path: target_socket,
                },
            ],
        })?;

        let connector = UdsConnector::new(gateway_socket);
        let client: Client<UdsConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);
        let req = Request::builder()
            .method(Method::POST)
            .uri("http://a2a.local/v1/agents/b/message:send")
            .header(AUTHORIZATION, "Bearer tok-a")
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(br#"{"ping":"pong"}"#)))?;
        let res = client.request(req).await?;
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await?.to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("\"caller\":\"a\""), "unexpected body: {text}");

        let _ = handle.stop()?;
        let _ = upstream_shutdown_tx.send(());
        Ok(())
    }
}
