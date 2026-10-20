//! Acceptance smoke harness: real HTTP transport and injected user/device decisions.
//! The injection seam is available ONLY to in-process test code, never over HTTP.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const WEB_ORIGIN: &str = "http://127.0.0.1:5173";

fn fixture_device() -> device::Device {
    device::Device {
        id: "usb-fixture-1".into(),
        model: "Simulated removable USB".into(),
        capacity_bytes: 31_457_280_000,
        bus_type: "USB".into(),
        partition_style: "GPT".into(),
        read_only: false,
    }
}
fn state_with_mock(
    approval: Approval,
    result: Result<Vec<device::Device>, device::DiscoveryError>,
) -> AppState {
    let mut state = AppState::new(WEB_ORIGIN.to_owned(), approval);
    // The production router has no endpoint for configuring this provider.
    // This is a test-only state override; the production default calls Windows Get-Disk.
    let response = Arc::new(Mutex::new(Some(result)));
    state.discover = Arc::new(move || {
        let response = response.clone();
        Box::pin(async move {
            let guard = response.lock().unwrap();
            // Permit independent repeated inventory requests with a known fixture.
            match guard.as_ref() {
                Some(Ok(drives)) => Ok(drives.clone()),
                Some(Err(device::DiscoveryError::Unsupported)) => {
                    Err(device::DiscoveryError::Unsupported)
                }
                Some(Err(device::DiscoveryError::Unavailable(detail))) => {
                    Err(device::DiscoveryError::Unavailable(detail.clone()))
                }
                None => Ok(vec![]),
            }
        })
    });
    state
}
async fn server(state: AppState) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    (format!("http://{addr}"), task)
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}
fn uri(base: &str, path: &str) -> String {
    format!("{base}/v1/{path}")
}
fn apply_headers(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    req.header("Host", format!("127.0.0.1:{PORT}"))
        .header("Origin", WEB_ORIGIN)
}
async fn grant(http: &reqwest::Client, base: &str) -> String {
    let response = apply_headers(http.post(uri(base, "access/request")))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["scope"], "devices:read");
    body["token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn real_http_approval_inventory_reconnect_and_revocation() {
    let prompts = Arc::new(AtomicUsize::new(0));
    let calls = prompts.clone();
    let state = state_with_mock(
        Arc::new(move |origin| {
            assert_eq!(origin, WEB_ORIGIN);
            calls.fetch_add(1, Ordering::SeqCst);
            true
        }),
        Ok(vec![fixture_device()]),
    );
    let (base, server_task) = server(state).await;
    let http = client();

    let response = apply_headers(http.get(uri(&base, "health")))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.json::<Value>().await.unwrap()["readOnly"], true);
    let response = apply_headers(http.get(uri(&base, "capabilities")))
        .send()
        .await
        .unwrap();
    let capability: Value = response.json().await.unwrap();
    assert_eq!(capability["diskWrite"], false);
    assert_eq!(capability["format"], false);
    assert_eq!(capability["partition"], false);

    assert_eq!(
        apply_headers(http.get(uri(&base, "devices")))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let session_a = grant(&http, &base).await;
    let session_b = grant(&http, &base).await;
    assert_ne!(session_a, session_b);
    assert_eq!(
        prompts.load(Ordering::SeqCst),
        1,
        "native approval must occur once per agent process"
    );

    for session in [&session_a, &session_b] {
        let response = apply_headers(http.get(uri(&base, "devices")).bearer_auth(session))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["devices"][0]["model"], "Simulated removable USB");
        assert_eq!(body["devices"][0]["capacityBytes"], 31_457_280_000_u64);
        assert_eq!(body["devices"].as_array().unwrap().len(), 1);
    }
    // A fake bearer, foreign Origin, or forged Host never reaches discovery.
    assert_eq!(
        apply_headers(http.get(uri(&base, "devices")).bearer_auth("wrong"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http.get(uri(&base, "devices"))
            .header("Host", format!("127.0.0.1:{PORT}"))
            .header("Origin", "https://malicious.example")
            .bearer_auth(&session_b)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        http.get(uri(&base, "devices"))
            .header("Host", "evil.example")
            .header("Origin", WEB_ORIGIN)
            .bearer_auth(&session_b)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    assert_eq!(
        apply_headers(
            http.post(uri(&base, "access/revoke"))
                .bearer_auth(&session_b)
        )
        .send()
        .await
        .unwrap()
        .status(),
        StatusCode::NO_CONTENT
    );
    for session in [&session_a, &session_b] {
        assert_eq!(
            apply_headers(http.get(uri(&base, "devices")).bearer_auth(session))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        apply_headers(http.post(uri(&base, "jobs")))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        apply_headers(http.post(uri(&base, "erase")))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        apply_headers(http.post(uri(&base, "format")))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    // A deliberate revocation requires a fresh native approval.
    let _again = grant(&http, &base).await;
    assert_eq!(prompts.load(Ordering::SeqCst), 2);
    server_task.abort();
}

#[tokio::test]
async fn real_http_denial_blocks_all_devices_and_locks_out() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    let state = state_with_mock(
        Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            false
        }),
        Ok(vec![fixture_device()]),
    );
    let (base, server_task) = server(state).await;
    let http = client();
    for _ in 0..MAX_DENIALS {
        assert_eq!(
            apply_headers(http.post(uri(&base, "access/request")))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        apply_headers(http.post(uri(&base, "access/request")))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(attempts.load(Ordering::SeqCst), usize::from(MAX_DENIALS));
    assert_eq!(
        apply_headers(http.get(uri(&base, "devices")))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    server_task.abort();
}

#[tokio::test]
async fn real_http_native_approval_cannot_run_twice_concurrently() {
    let state = state_with_mock(
        Arc::new(|_| {
            std::thread::sleep(Duration::from_millis(180));
            true
        }),
        Ok(vec![]),
    );
    let (base, server_task) = server(state).await;
    let http = client();
    let first = tokio::spawn({
        let http = http.clone();
        let target = uri(&base, "access/request");
        async move { apply_headers(http.post(target)).send().await.unwrap() }
    });
    tokio::time::sleep(Duration::from_millis(35)).await;
    let second = apply_headers(http.post(uri(&base, "access/request")))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
    server_task.abort();
}

#[tokio::test]
async fn real_http_discovery_failure_is_not_a_success() {
    let state = state_with_mock(
        Arc::new(|_| true),
        Err(device::DiscoveryError::Unavailable("mocked failure".into())),
    );
    let (base, server_task) = server(state).await;
    let http = client();
    let session = grant(&http, &base).await;
    let response = apply_headers(http.get(uri(&base, "devices")).bearer_auth(session))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "discovery_unavailable"
    );
    server_task.abort();
}

#[cfg(windows)]
#[tokio::test]
async fn windows_native_get_disk_read_only_smoke() {
    // This executes genuine Windows PowerShell Storage discovery on a Windows CI
    // runner. No disk open-for-write, format, volume unmount, or elevation occurs.
    let result = device::discover().await;
    let drives = result.expect("Windows Get-Disk should provide a parseable read-only inventory");
    assert!(
        drives
            .iter()
            .all(|d| d.bus_type == "USB" && d.capacity_bytes > 0)
    );
    assert!(
        drives
            .iter()
            .all(|d| !d.id.is_empty() && !d.model.is_empty())
    );
}
