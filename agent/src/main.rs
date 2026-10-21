#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
//! BootNexa read-only companion agent: local approval, no disk writes.
mod device;
mod sim_api;
#[cfg(test)]
mod smoke_tests;
#[cfg(test)]
mod tests;
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rand::random;
use serde_json::{Value, json};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
const PORT: u16 = 43627;
const TOKEN_TTL: Duration = Duration::from_secs(1800);
const MAX_DENIALS: u8 = 5;
type Approval = Arc<dyn Fn(&str) -> bool + Send + Sync>;
type Discovery = Arc<
    dyn Fn() -> Pin<
            Box<dyn Future<Output = Result<Vec<device::Device>, device::DiscoveryError>> + Send>,
        > + Send
        + Sync,
>;

#[derive(Clone)]
struct AppState {
    origin: String,
    auth: Arc<Mutex<Auth>>,
    approve: Approval,
    discover: Discovery,
    simulations: Option<Arc<bootnexa_agent::journal::JobStore>>,
}
struct Session {
    token: String,
    expiry: Instant,
}
struct Auth {
    approved: bool,
    pending: bool,
    denials: u8,
    sessions: Vec<Session>,
}
impl AppState {
    fn new(origin: String, approve: Approval) -> Self {
        Self {
            origin,
            auth: Arc::new(Mutex::new(Auth {
                approved: false,
                pending: false,
                denials: 0,
                sessions: Vec::new(),
            })),
            approve,
            discover: Arc::new(|| Box::pin(device::discover())),
            simulations: None,
        }
    }
}
fn valid_origin(origin: &str) -> bool {
    let Ok(url) = url::Url::parse(origin) else {
        return false;
    };
    let local = url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    (url.scheme() == "https" || local)
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.origin().ascii_serialization() == origin
}
fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/access/request", post(access_request))
        .route("/v1/access/revoke", post(revoke))
        .route("/v1/devices", get(devices))
        .route("/v1/simulations/{id}", get(sim_api::snapshot))
        .route("/v1/simulations/{id}/events", get(sim_api::events))
        .route("/v1/simulations/{id}/stream", get(sim_api::stream))
        .layer(DefaultBodyLimit::max(512))
        .layer(middleware::from_fn_with_state(state.clone(), boundary))
        .with_state(state)
}
fn err(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({"error":code}))).into_response()
}
fn cors(response: &mut Response, origin: &str) {
    if let Ok(v) = HeaderValue::from_str(origin) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
    }
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("authorization, content-type"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("access-control-allow-private-network"),
        HeaderValue::from_static("true"),
    );
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Origin"));
}
async fn boundary(State(state): State<AppState>, request: Request<Body>, next: Next) -> Response {
    if request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        != Some(format!("127.0.0.1:{PORT}").as_str())
    {
        return err(StatusCode::FORBIDDEN, "invalid_host");
    }
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    if origin.is_some_and(|v| v != state.origin) {
        return err(StatusCode::FORBIDDEN, "origin_not_allowed");
    }
    if (matches!(
        request.uri().path(),
        "/v1/devices" | "/v1/access/request" | "/v1/access/revoke"
    ) || request.uri().path().starts_with("/v1/simulations/"))
        && origin != Some(state.origin.as_str())
    {
        return err(StatusCode::FORBIDDEN, "origin_required");
    }
    if request.method() == Method::OPTIONS {
        if origin != Some(state.origin.as_str()) {
            return err(StatusCode::FORBIDDEN, "origin_required");
        }
        let mut response = StatusCode::NO_CONTENT.into_response();
        cors(&mut response, &state.origin);
        return response;
    }
    let allowed = origin == Some(state.origin.as_str());
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if allowed {
        cors(&mut response, &state.origin)
    }
    response
}
async fn health() -> Json<Value> {
    Json(
        json!({"name":"BootNexa Agent","protocolVersion":"0.2","version":env!("CARGO_PKG_VERSION"),"status":"ready","platform":std::env::consts::OS,"readOnly":true}),
    )
}
async fn capabilities() -> Json<Value> {
    Json(
        json!({"protocolVersion":"0.2","deviceDiscovery":cfg!(windows),"diskWrite":false,"format":false,"partition":false,"imageAnalysis":false,"access":"native_approval","sessionExpiresSeconds":TOKEN_TTL.as_secs()}),
    )
}
fn mint(guard: &mut Auth) -> Value {
    let token = hex::encode(random::<[u8; 32]>());
    guard.sessions.retain(|s| Instant::now() < s.expiry);
    if guard.sessions.len() >= 8 {
        guard.sessions.remove(0);
    }
    guard.sessions.push(Session {
        token: token.clone(),
        expiry: Instant::now() + TOKEN_TTL,
    });
    json!({"token":token,"scope":"devices:read","expiresInSeconds":TOKEN_TTL.as_secs()})
}
async fn access_request(State(state): State<AppState>) -> Response {
    if !cfg!(windows) && !cfg!(test) {
        return err(StatusCode::NOT_IMPLEMENTED, "windows_agent_required");
    }
    {
        let mut guard = state.auth.lock().unwrap_or_else(|e| e.into_inner());
        if guard.denials >= MAX_DENIALS {
            return err(StatusCode::TOO_MANY_REQUESTS, "too_many_denials");
        }
        if guard.pending {
            return err(StatusCode::CONFLICT, "approval_pending");
        }
        if guard.approved {
            return (StatusCode::OK, Json(mint(&mut guard))).into_response();
        }
        guard.pending = true;
    }
    let origin = state.origin.clone();
    let approve = state.approve.clone();
    let outcome = tokio::task::spawn_blocking(move || (approve)(&origin)).await;
    let mut guard = state.auth.lock().unwrap_or_else(|e| e.into_inner());
    guard.pending = false;
    if !matches!(outcome, Ok(true)) {
        guard.denials = guard.denials.saturating_add(1);
        return err(StatusCode::FORBIDDEN, "user_denied");
    }
    guard.approved = true;
    (StatusCode::OK, Json(mint(&mut guard))).into_response()
}
fn authorised(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    let guard = state.auth.lock().unwrap_or_else(|e| e.into_inner());
    guard.sessions.iter().any(|session| {
        Instant::now() < session.expiry
            && bool::from(token.as_bytes().ct_eq(session.token.as_bytes()))
    })
}
async fn revoke(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorised(&state, &headers) {
        return err(StatusCode::UNAUTHORIZED, "not_authorised");
    }
    let mut guard = state.auth.lock().unwrap_or_else(|e| e.into_inner());
    guard.sessions.clear();
    guard.approved = false;
    StatusCode::NO_CONTENT.into_response()
}
async fn devices(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorised(&state, &headers) {
        return err(StatusCode::UNAUTHORIZED, "not_authorised");
    }
    match (state.discover)().await {
        Ok(drives) => Json(json!({"devices":drives,"readOnly":true})).into_response(),
        Err(device::DiscoveryError::Unsupported) => {
            err(StatusCode::NOT_IMPLEMENTED, "windows_agent_required")
        }
        Err(device::DiscoveryError::Unavailable(_)) => {
            err(StatusCode::SERVICE_UNAVAILABLE, "discovery_unavailable")
        }
    }
}
#[cfg(windows)]
fn native_approve(origin: &str) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONQUESTION, MB_TOPMOST, MB_YESNO, MessageBoxW,
    };
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
    let title = wide("BootNexa - USB access");
    let message = wide(&format!(
        "Allow BootNexa to VIEW removable USB devices?\n\nWebsite: {origin}\n\nRead-only access for this agent process. No erasing, writing or formatting is possible in this version.\n\nOnly approve if you opened BootNexa yourself."
    ));
    // Interactive per-user process: Windows services running in Session 0 cannot display this dialog.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_TOPMOST,
        ) == IDYES
    }
}
#[cfg(not(windows))]
fn native_approve(_: &str) -> bool {
    false
}
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let origin = std::env::var("BOOTNEXA_ALLOWED_ORIGIN")
        .unwrap_or_else(|_| "http://127.0.0.1:5173".to_owned());
    if !valid_origin(&origin) {
        eprintln!(
            "Invalid BOOTNEXA_ALLOWED_ORIGIN. Use a canonical HTTPS or local loopback origin."
        );
        std::process::exit(2)
    }
    println!(
        "BootNexa agent {} (read-only)\nAllowed origin: {origin}\nNative approval required before listing USB devices; no pairing code.",
        env!("CARGO_PKG_VERSION")
    );
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), PORT))
            .await?;
    let mut state = AppState::new(origin, Arc::new(native_approve));
    // Explicit developer opt-in. Off in production by default. These routes
    // only disclose simulation history, never create jobs or touch USB disks.
    if std::env::var("BOOTNEXA_ENABLE_SIMULATIONS").as_deref() == Ok("1") {
        let path = std::env::var("BOOTNEXA_SIMULATION_DB")
            .expect("BOOTNEXA_SIMULATION_DB required for opt-in simulations");
        let store =
            bootnexa_agent::journal::JobStore::open(path).expect("cannot open simulator database");
        let interrupted = store
            .recover_interrupted()
            .expect("cannot perform startup recovery");
        println!(
            "Simulation-only SQLite feed enabled ({} interrupted jobs recovered).",
            interrupted
        );
        state.simulations = Some(Arc::new(store));
    }
    axum::serve(listener, router(state)).await
}
