//! Developer-only read side of the durable simulated journal.
//! No HTTP creation, mutation, physical disk or file image access.
use crate::{AppState, authorised, err};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse, Response,
        sse::{Event as SseEvent, KeepAlive, Sse},
    },
};
use bootnexa_agent::journal::{Event, JobStore, JournalError};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{convert::Infallible, sync::Arc, time::Duration};

#[derive(Deserialize)]
pub struct Cursor {
    #[serde(default)]
    after: i64,
    limit: Option<usize>,
}
fn body_event(value: &Event) -> Value {
    json!({
        "sequence": value.sequence, "jobId": value.job_id,
        "phase": value.phase.as_str(), "completedBytes": value.completed_bytes,
        "verifiedBytes": value.verified_bytes, "code": value.code,
        "atMs":value.at_ms, "simulationOnly":true,
    })
}
fn problem(e: &JournalError) -> Response {
    match e {
        JournalError::NotFound => err(StatusCode::NOT_FOUND, "simulation_not_found"),
        JournalError::InvalidCursor => err(StatusCode::BAD_REQUEST, "invalid_cursor"),
        _ => err(StatusCode::SERVICE_UNAVAILABLE, "simulation_unavailable"),
    }
}
fn require(state: &AppState, headers: &HeaderMap) -> Result<Arc<JobStore>, Box<Response>> {
    // Disabled mode is indistinguishable from a missing optional endpoint.
    let store = state
        .simulations
        .clone()
        .ok_or_else(|| Box::new(err(StatusCode::NOT_FOUND, "simulation_disabled")))?;
    if !authorised(state, headers) {
        return Err(Box::new(err(StatusCode::UNAUTHORIZED, "not_authorised")));
    }
    Ok(store)
}
fn snapshot_body(job: &bootnexa_agent::journal::Job) -> Value {
    json!({
        "simulationOnly":true,"id":job.id,
        "phase":job.phase.as_str(),"sourceSha256":job.source_sha256,
        "simulatedTarget":job.simulated_target,
        "expectedBytes":job.expected_bytes,
        "completedBytes":job.completed_bytes,
        "verifiedBytes":job.verified_bytes,
        "flushSimulated":job.flush_recorded,
        "rollingSha256":job.rolling_sha256,
        "failureCode":job.failure_code,
        "createdAtMs":job.created_at_ms,"updatedAtMs":job.updated_at_ms,
    })
}
pub async fn snapshot(
    Path(id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let store = match require(&state, &headers) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    match tokio::task::spawn_blocking(move || store.get(&id)).await {
        Ok(Ok(job)) => Json(snapshot_body(&job)).into_response(),
        Ok(Err(e)) => problem(&e),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "simulation_unavailable"),
    }
}
pub async fn events(
    Path(id): Path<String>,
    Query(cursor): Query<Cursor>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let store = match require(&state, &headers) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    let after = cursor.after;
    let limit = cursor.limit.unwrap_or(100);
    match tokio::task::spawn_blocking(move || store.events_after(&id, after, limit)).await {
        Ok(Ok(events)) => {
            let next = events.last().map(|e| e.sequence).unwrap_or(after);
            Json(json!({"simulationOnly":true,"events":events.iter().map(body_event).collect::<Vec<_>>(),
                "nextCursor":next})).into_response()
        }
        Ok(Err(e)) => problem(&e),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "simulation_unavailable"),
    }
}
pub async fn stream(
    Path(id): Path<String>,
    Query(cursor): Query<Cursor>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let store = match require(&state, &headers) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    if cursor.after < 0 || cursor.limit.is_some_and(|n| !(1..=100).contains(&n)) {
        return problem(&JournalError::InvalidCursor);
    }
    let target = store.clone();
    let lookup = id.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || target.get(&lookup))
        .await
        .unwrap_or(Err(JournalError::InvalidRequest))
    {
        return problem(&e);
    }
    let live = async_stream::stream! {
        let mut after=cursor.after;
        let mut interval=tokio::time::interval(Duration::from_millis(350));
        // Streams are bounded; reconnect using last EventSource id. The event
        // replay cursor is persisted in SQLite and monotonic across restarts.
        let deadline=tokio::time::Instant::now()+Duration::from_secs(120);
        loop {
            if tokio::time::Instant::now()>deadline {break;}
            interval.tick().await;
            let target=store.clone();
            let job_id=id.clone();
            let result=tokio::task::spawn_blocking(move ||target.events_after(&job_id,after,100)).await;
            let events=match result {
                Ok(Ok(events))=>events,
                _=>break, // no raw database error details cross the API
            };
            for entry in &events {
                after=entry.sequence;
                if let Ok(data)=serde_json::to_string(&body_event(entry)) {
                    yield Ok::<SseEvent,Infallible>(SseEvent::default().event("simulation").id(after.to_string()).data(data));
                }
            }
            let target=store.clone();
            let job_id=id.clone();
            if let Ok(Ok(snapshot))=tokio::task::spawn_blocking(move ||target.get(&job_id)).await {
                if snapshot.phase.terminal() && events.is_empty() {break;}
            } else {break;}
        }
    };
    Sse::new(live)
        .keep_alive(KeepAlive::default().interval(Duration::from_secs(10)))
        .into_response()
}
