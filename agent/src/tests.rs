use super::*;
use axum::{body::to_bytes, http::Request};
use tower::ServiceExt;
const ORIGIN: &str = "http://127.0.0.1:5173";
fn req(path: &str, method: Method, origin: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, format!("127.0.0.1:{PORT}"));
    if let Some(origin) = origin {
        b = b.header(header::ORIGIN, origin)
    }
    b.body(Body::empty()).unwrap()
}
fn token(mut r: Request<Body>, value: &str) -> Request<Body> {
    r.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {value}")).unwrap(),
    );
    r
}
async fn json(res: Response) -> Value {
    serde_json::from_slice(&to_bytes(res.into_body(), 4096).await.unwrap()).unwrap()
}
fn state(allow: bool) -> AppState {
    AppState::new(ORIGIN.into(), Arc::new(move |_| allow))
}
#[test]
fn origin_is_strict() {
    assert!(valid_origin(ORIGIN));
    assert!(valid_origin("https://app.example.com"));
    for s in [
        "http://evil.example.com",
        "https://user@safe.example.com",
        "https://safe.example.com/path",
        "https://safe.example.com/",
        "*",
    ] {
        assert!(!valid_origin(s), "{s}")
    }
}
#[tokio::test]
async fn origin_host_and_cors() {
    let app = router(state(true));
    assert_eq!(
        app.clone()
            .oneshot(req(
                "/v1/access/request",
                Method::POST,
                Some("https://evil.example")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(req("/v1/access/request", Method::POST, None))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(req("/v1/devices", Method::GET, None))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut spoof = req("/v1/health", Method::GET, None);
    spoof
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static("evil.example"));
    assert_eq!(
        app.clone().oneshot(spoof).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let preflight = app
        .clone()
        .oneshot(req("/v1/access/request", Method::OPTIONS, Some(ORIGIN)))
        .await
        .unwrap();
    assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        preflight
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        ORIGIN
    );
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-private-network")
            .unwrap(),
        "true"
    );
}
#[tokio::test]
async fn approval_scopes_reconnect_and_revoke() {
    let app = router(state(true));
    assert_eq!(
        app.clone()
            .oneshot(req("/v1/devices", Method::GET, Some(ORIGIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let approved = app
        .clone()
        .oneshot(req("/v1/access/request", Method::POST, Some(ORIGIN)))
        .await
        .unwrap();
    assert_eq!(approved.status(), StatusCode::OK);
    let first = json(approved).await["token"].as_str().unwrap().to_string();
    assert_eq!(first.len(), 64);
    let access = app
        .clone()
        .oneshot(token(req("/v1/devices", Method::GET, Some(ORIGIN)), &first))
        .await
        .unwrap();
    assert!(matches!(
        access.status(),
        StatusCode::OK | StatusCode::NOT_IMPLEMENTED | StatusCode::SERVICE_UNAVAILABLE
    ));
    let again = app
        .clone()
        .oneshot(req("/v1/access/request", Method::POST, Some(ORIGIN)))
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::OK);
    let second = json(again).await["token"].as_str().unwrap().to_string();
    assert_ne!(first, second);
    let first_still_valid = app
        .clone()
        .oneshot(token(req("/v1/devices", Method::GET, Some(ORIGIN)), &first))
        .await
        .unwrap();
    assert!(matches!(
        first_still_valid.status(),
        StatusCode::OK | StatusCode::NOT_IMPLEMENTED | StatusCode::SERVICE_UNAVAILABLE
    ));
    assert_eq!(
        app.clone()
            .oneshot(token(
                req("/v1/access/revoke", Method::POST, Some(ORIGIN)),
                &second
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.clone()
            .oneshot(token(
                req("/v1/devices", Method::GET, Some(ORIGIN)),
                &second
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(token(req("/v1/devices", Method::GET, Some(ORIGIN)), &first))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(req("/v1/jobs", Method::POST, Some(ORIGIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}
#[tokio::test]
async fn denial_and_rate_limit() {
    let app = router(state(false));
    for _ in 0..MAX_DENIALS {
        assert_eq!(
            app.clone()
                .oneshot(req("/v1/access/request", Method::POST, Some(ORIGIN)))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        app.clone()
            .oneshot(req("/v1/access/request", Method::POST, Some(ORIGIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn simulation_routes_require_origin_and_bearer_and_replay_persisted_events() {
    use bootnexa_agent::journal::{JobRequest, JobStore, Phase};
    let dir = tempfile::tempdir().unwrap();
    let store = JobStore::open(dir.path().join("read-side.sqlite")).unwrap();
    let j = store
        .create(&JobRequest {
            idempotency_key: "http-acceptance-0001".into(),
            source_sha256: "a".repeat(64),
            simulated_target: "b".repeat(64),
            expected_bytes: 4096,
        })
        .unwrap();
    store.advance(&j.id, Phase::Preflighted).unwrap();
    // Terminal job: SSE should replay and close, rather than streaming forever.
    store.cancel(&j.id).unwrap();
    let mut s = state(true);
    s.simulations = Some(Arc::new(store));
    let app = router(s);
    let path = format!("/v1/simulations/{}", j.id);
    assert_eq!(
        app.clone()
            .oneshot(req(&path, Method::GET, None))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(req(&path, Method::GET, Some(ORIGIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(req(&path, Method::POST, Some(ORIGIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    let access = app
        .clone()
        .oneshot(req("/v1/access/request", Method::POST, Some(ORIGIN)))
        .await
        .unwrap();
    let key = json(access).await["token"].as_str().unwrap().to_owned();
    let snap = app
        .clone()
        .oneshot(token(req(&path, Method::GET, Some(ORIGIN)), &key))
        .await
        .unwrap();
    assert_eq!(snap.status(), StatusCode::OK);
    let data = json(snap).await;
    assert_eq!(data["simulationOnly"], true);
    assert_eq!(data["phase"], "CANCELLED");
    let path_events = format!("{path}/events?after=0");
    let events = app
        .clone()
        .oneshot(token(req(&path_events, Method::GET, Some(ORIGIN)), &key))
        .await
        .unwrap();
    assert_eq!(events.status(), StatusCode::OK);
    let items = json(events).await;
    assert_eq!(items["events"].as_array().unwrap().len(), 3);
    let cursor = items["events"][0]["sequence"].as_i64().unwrap();
    let path_later = format!("{path}/events?after={cursor}&limit=1");
    let later = json(
        app.clone()
            .oneshot(token(req(&path_later, Method::GET, Some(ORIGIN)), &key))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(later["events"].as_array().unwrap().len(), 1);
    assert_eq!(later["events"][0]["phase"], "PREFLIGHTED");
    let invalid = format!("{path}/events?after=-1");
    let bad = app
        .clone()
        .oneshot(token(req(&invalid, Method::GET, Some(ORIGIN)), &key))
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let sse_path = format!("{path}/stream?after=0");
    let sse = app
        .clone()
        .oneshot(token(req(&sse_path, Method::GET, Some(ORIGIN)), &key))
        .await
        .unwrap();
    assert_eq!(sse.status(), StatusCode::OK);
    assert!(
        sse.headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/event-stream")
    );
    let raw =
        String::from_utf8(to_bytes(sse.into_body(), 64 * 1024).await.unwrap().to_vec()).unwrap();
    assert!(raw.contains("event: simulation"));
    assert!(!raw.contains("SIMULATED"));
    assert!(raw.contains("CANCELLED"));
    let revoke = app
        .clone()
        .oneshot(token(
            req("/v1/access/revoke", Method::POST, Some(ORIGIN)),
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::NO_CONTENT);
    let denied = app
        .clone()
        .oneshot(token(req(&path, Method::GET, Some(ORIGIN)), &key))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn simulation_routes_disabled_by_default() {
    let app = router(state(true));
    let r = app
        .oneshot(req(
            "/v1/simulations/no-such-job",
            Method::GET,
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn read_only_simulation_listing_is_bounded_and_requires_active_grant() {
    use bootnexa_agent::journal::{JobRequest, JobStore};
    let dir = tempfile::tempdir().unwrap();
    let store = JobStore::open(dir.path().join("listing.sqlite")).unwrap();
    let j = store
        .create(&JobRequest {
            idempotency_key: "list-job-001".into(),
            source_sha256: "a".repeat(64),
            simulated_target: "b".repeat(64),
            expected_bytes: 1024,
        })
        .unwrap();
    let mut s = state(true);
    s.simulations = Some(Arc::new(store));
    let app = router(s);
    let path = "/v1/simulations?limit=1";
    assert_eq!(
        app.clone()
            .oneshot(req(path, Method::GET, None))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(req(path, Method::GET, Some(ORIGIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let first = json(
        app.clone()
            .oneshot(req("/v1/access/request", Method::POST, Some(ORIGIN)))
            .await
            .unwrap(),
    )
    .await;
    let key = first["token"].as_str().unwrap();
    let snapshot = json(
        app.clone()
            .oneshot(token(req(path, Method::GET, Some(ORIGIN)), key))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(snapshot["simulationOnly"], true);
    assert_eq!(snapshot["jobs"][0]["id"], j.id);
    assert_eq!(snapshot["jobs"][0]["phase"], "CREATED");
    assert_eq!(
        app.clone()
            .oneshot(token(
                req("/v1/simulations?limit=101", Method::GET, Some(ORIGIN)),
                key
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.clone()
            .oneshot(token(
                req("/v1/simulations", Method::POST, Some(ORIGIN)),
                key
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        app.clone()
            .oneshot(token(
                req("/v1/access/revoke", Method::POST, Some(ORIGIN)),
                key
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.oneshot(token(req(path, Method::GET, Some(ORIGIN)), key))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}
