use crate::state::ApiAppState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use tokio::sync::broadcast::error::RecvError;

pub async fn ws_events_handler(
    ws: WebSocketUpgrade,
    State(app): State<ApiAppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, app))
}

async fn handle_ws_connection(mut socket: WebSocket, app: ApiAppState) {
    let mut rx = app.backend.subscribe_ws();
    let welcome = serde_json::json!({
        "event_type": "CONNECTED",
        "network": app.backend.network_info().await,
    });
    if socket
        .send(Message::Text(welcome.to_string()))
        .await
        .is_err()
    {
        return;
    }
    loop {
        match rx.recv().await {
            Ok(ev) => {
                if let Ok(txt) = serde_json::to_string(&ev) {
                    if socket.send(Message::Text(txt)).await.is_err() {
                        break;
                    }
                }
            }
            Err(RecvError::Lagged(skipped)) => {
                let notice = serde_json::json!({
                    "event_type": "STREAM_LAGGED",
                    "skipped": skipped,
                });
                if socket
                    .send(Message::Text(notice.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(RecvError::Closed) => break,
        }
    }
}
