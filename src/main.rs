use std::{env, net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde::Deserialize;
use serde_json::Value;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

struct AppState {
    webhook_url: String,
    token: String,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct SlackMessage {
    text: Option<String>,
}

#[derive(Deserialize)]
struct TaskNotification {
    task: String,
    status: String,
    root_url: String,
    task_id: String,
    task_group_id: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "slackord=info,tower_http=debug".parse().unwrap()),
        )
        .init();

    let webhook_url = env::var("DISCORD_WEBHOOK_URL").expect("DISCORD_WEBHOOK_URL must be set");
    let token = env::var("SLACK_TOKEN").expect("SLACK_TOKEN must be set");
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(2364);

    let state = Arc::new(AppState {
        webhook_url,
        token,
        http: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/chat.postMessage", post(handle_post_message))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_post_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<Value>) {
    tracing::debug!(%body, "raw request body");

    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if provided != Some(&state.token) {
        warn!("rejected: invalid or missing token");
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "invalid_auth" })),
        );
    }

    let msg: SlackMessage = match serde_urlencoded::from_str(&body) {
        Ok(m) => m,
        Err(e) => {
            warn!(%e, "failed to parse request body");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": "invalid_form" })),
            );
        }
    };

    let text = msg.text.as_deref().unwrap_or("");
    let embed = match serde_json::from_str::<TaskNotification>(text) {
        Ok(notif) => build_embed(&notif),
        Err(_) => {
            warn!("text is not valid JSON, forwarding as plain text");
            serde_json::json!({ "description": text, "color": 0x4A154B })
        }
    };

    let payload = serde_json::json!({ "embeds": [embed] });
    match state
        .http
        .post(&state.webhook_url)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!("forwarded to discord");
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(%status, %body, "discord returned non-success");
        }
        Err(e) => {
            error!(%e, "failed to forward to discord");
        }
    }

    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

fn build_embed(notif: &TaskNotification) -> Value {
    let emoji = match notif.status.as_str() {
        "completed" => "✅",
        "failed" => "❌",
        "exception" => "⚠️",
        _ => "❔",
    };
    let color: u32 = match notif.status.as_str() {
        "completed" => 0x2ECC71,
        "failed" => 0xE74C3C,
        "exception" => 0xF39C12,
        _ => 0x4A154B,
    };
    let task_url = format!("{}/tasks/{}", notif.root_url, notif.task_id);
    let description = format!(
        "{emoji} **[{}]({task_url})** completed: **{}**",
        notif.task, notif.status
    );

    serde_json::json!({
        "description": description,
        "color": color,
        "footer": { "text": format!("Task group {}", notif.task_group_id) },
    })
}
