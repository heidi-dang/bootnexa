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
