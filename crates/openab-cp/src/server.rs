//! WebSocket server: authentication at upgrade, mandatory `cp/register`
//! first frame, then frame dispatch to registry/policy/router.
//!
//! Auth: the runtime presents its key as `Authorization: Bearer <key>` on the
//! upgrade request. Keys never appear in URLs (avoids access-log leakage).
//!
//! Resource bounds (review F5): the WS transport enforces
//! `max_frame_bytes` before parsing; each connection's outbound queue is
//! bounded — a peer that cannot drain it is treated as disconnected.
//!
//! Admission bounds (review round-3 F4): authentication alone is not a
//! bound. Every connection holds a per-identity slot from the upgrade until
//! it ends (`ConnPermit`, released on every exit path), and must complete
//! `cp/register` within `register_timeout_secs` or be closed.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router as AxumRouter;
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::config::{AgentIdentity, CpConfig};
use crate::events::EventHub;
use crate::proto::{
    codes, methods, AgentSummary, AgentType, CancelParams, CpEvent, DelegateParams,
    DelegateResultParams, DeregisterReason, ErrorObject, JsonRpcErrorResponse, JsonRpcMessage,
    JsonRpcResponse, ListAgentsResult, RegisterAck, RegisterParams, PROTOCOL_VERSION,
};
use crate::registry::{shutdown_signal, Instance, Registry, OUTBOUND_QUEUE};
use crate::router::{DelegateOutcome, Router};

pub struct AppState {
    pub cfg: CpConfig,
    pub registry: Registry,
    pub router: Router,
    /// Observer fan-out (`cp/event`) with per-namespace sequence numbers.
    pub events: EventHub,
    rpc_id: AtomicU64,
    /// Live connections per identity (`namespace/name`), counted from the
    /// upgrade so pre-registration sockets are bounded too (review round-3
    /// F4).
    conns: Mutex<BTreeMap<String, u32>>,
}

impl AppState {
    pub fn new(cfg: CpConfig) -> Self {
        Self {
            events: EventHub::new(&cfg),
            cfg,
            registry: Registry::new(),
            router: Router::new(),
            rpc_id: AtomicU64::new(1),
            conns: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn next_rpc_id(&self) -> u64 {
        self.rpc_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Take a connection slot for `identity`, or `None` when the identity is
    /// already at `max_connections_per_identity`. The returned guard releases
    /// the slot on drop — including on every early return and on an upgrade
    /// that never completes (review round-3 F4).
    pub fn try_acquire_conn(self: &Arc<Self>, identity: &AgentIdentity) -> Option<ConnPermit> {
        let key = format!("{}/{}", identity.namespace, identity.name);
        let mut g = self.conns.lock();
        let n = g.entry(key.clone()).or_insert(0);
        if *n >= self.cfg.max_connections_per_identity {
            return None;
        }
        *n += 1;
        Some(ConnPermit {
            state: Arc::clone(self),
            key,
        })
    }

    /// Live connection count for an identity (`namespace/name`).
    pub fn conn_count(&self, logical_id: &str) -> u32 {
        self.conns.lock().get(logical_id).copied().unwrap_or(0)
    }
}

/// RAII connection slot. Dropping it frees the identity's quota; it is never
/// released explicitly, so no early return can leak it (review round-3 F4).
pub struct ConnPermit {
    state: Arc<AppState>,
    key: String,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut g = self.state.conns.lock();
        if let Some(n) = g.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.remove(&self.key);
            }
        }
    }
}

pub fn app(state: Arc<AppState>) -> AxumRouter {
    AxumRouter::new()
        .route("/cp", get(ws_handler))
        .route("/health", get(health))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn ws_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let identity = match key.and_then(|k| state.cfg.identity_for_key(k)) {
        Some(id) => id.clone(),
        None => {
            warn!("WS rejected: missing or unknown auth key");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    // Per-identity connection quota, taken before the upgrade so an
    // over-quota peer is refused at the HTTP layer (review round-3 F4).
    let permit = match state.try_acquire_conn(&identity) {
        Some(p) => p,
        None => {
            warn!(
                agent = %format!("{}/{}", identity.namespace, identity.name),
                max = state.cfg.max_connections_per_identity,
                "WS rejected: identity is at its connection quota"
            );
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let max_frame = state.cfg.max_frame_bytes;
    ws.max_message_size(max_frame)
        .max_frame_size(max_frame)
        .on_upgrade(move |socket| handle_connection(state, socket, identity, permit))
}

async fn handle_connection(
    state: Arc<AppState>,
    socket: WebSocket,
    identity: AgentIdentity,
    // Held for the connection's whole lifetime; dropped here on every exit
    // path, including the early returns below (review round-3 F4).
    _permit: ConnPermit,
) {
    let (mut sink, mut stream) = socket.split();

    // --- Registration: mandatory first frame, within a deadline ---
    // An authenticated peer must not be able to park idle sockets: pings keep
    // the transport alive but do not extend this deadline (review round-3 F4).
    let register = match tokio::time::timeout(
        Duration::from_secs(state.cfg.register_timeout_secs),
        async {
            loop {
                match stream.next().await {
                    Some(Ok(Message::Text(text))) => return Some(text),
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                    _ => return None,
                }
            }
        },
    )
    .await
    {
        Ok(Some(text)) => text,
        Ok(None) => {
            warn!(agent = %identity.name, "connection closed before registration");
            return;
        }
        Err(_) => {
            warn!(
                agent = %format!("{}/{}", identity.namespace, identity.name),
                timeout_secs = state.cfg.register_timeout_secs,
                "no cp/register within the registration deadline — closing"
            );
            let _ = sink.send(Message::Close(None)).await;
            return;
        }
    };
    let (reg, reg_rpc_id) = match parse_register(&register, &identity) {
        Ok(ok) => ok,
        Err((id, err)) => {
            let resp = JsonRpcErrorResponse::new(id, err);
            let _ = sink
                .send(Message::Text(
                    serde_json::to_string(&resp).expect("serializable").into(),
                ))
                .await;
            return;
        }
    };

    // Outbound channel for this connection. Bounded (review F5): a peer that
    // cannot drain OUTBOUND_QUEUE frames is disconnected, not buffered.
    let (tx, mut rx) = mpsc::channel::<String>(OUTBOUND_QUEUE);

    // Shutdown signal so the CP can close this socket when it drops the
    // registration on its own initiative (lease expiry — review round-3 F1).
    // Subscribed BEFORE registering so no signal can be missed, and kept
    // alive here for the whole connection: closing is driven by an explicit
    // signal, never by the registry happening to drop its side.
    let shutdown = shutdown_signal();
    let mut shutdown_rx = shutdown.subscribe();

    let effective_max = match identity.max_delegated_sessions_cap {
        Some(cap) => reg.max_delegated_sessions.min(cap),
        None => reg.max_delegated_sessions,
    };
    // The registry assigns the CP-generated handle (review F1): ownership
    // and teardown never key on the client-supplied instance_id.
    let handle = state.registry.register_conn(
        Instance {
            handle: 0,
            namespace: identity.namespace.clone(),
            name: identity.name.clone(),
            agent_type: identity.agent_type.clone(),
            instance_id: reg.instance_id.clone(),
            labels: reg.labels.clone(),
            max_delegated_sessions: effective_max,
            active_sessions: 0,
            registered_at: Instant::now(),
            last_heartbeat: Instant::now(),
            tx: tx.clone(),
        },
        Arc::clone(&shutdown),
    );
    info!(
        agent = %format!("{}/{}", identity.namespace, identity.name),
        instance = %reg.instance_id,
        handle,
        r#type = %identity.agent_type,
        max_sessions = effective_max,
        "registered"
    );

    // Ack. The CP-generated handle is intentionally not disclosed.
    let ack = RegisterAck {
        protocol_version: PROTOCOL_VERSION,
        heartbeat_interval_secs: state.cfg.heartbeat_interval_secs,
        lease_expiry_secs: state.cfg.lease_expiry_secs,
        effective_max_delegated_sessions: effective_max,
    };
    let resp = JsonRpcResponse::new(
        reg_rpc_id,
        serde_json::to_value(&ack).expect("serializable"),
    );
    if sink
        .send(Message::Text(
            serde_json::to_string(&resp).expect("serializable").into(),
        ))
        .await
        .is_err()
    {
        teardown(&state, handle, &identity);
        return;
    }

    // The lobby learns about every arrival — observers included, so one
    // lobby client sees the others.
    announce_registration(&state, handle);

    // --- Main loop: interleave inbound frames, outbound channel, shutdown ---
    let mut cp_closed = false;
    loop {
        tokio::select! {
            // The CP dropped this registration (lease expiry): the socket
            // must go too (review round-3 F1). Keeping it open would leave a
            // connection whose every frame hits an absent registry entry and
            // which can never re-register, since registration is
            // first-frame-only. Closing lets the client reconnect,
            // re-authenticate, and register again.
            _ = shutdown_rx.changed() => {
                cp_closed = true;
                break;
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(text) => {
                        if sink.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            inbound = stream.next() => {
                match inbound {
                    Some(Ok(Message::Text(text))) => {
                        if let Some(reply) = handle_frame(&state, handle, &text) {
                            if sink.send(Message::Text(reply.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        if sink.send(Message::Pong(p)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // binary/pong ignored
                    Some(Err(e)) => {
                        warn!(handle, err = %e, "WS error");
                        break;
                    }
                }
            }
        }
    }

    if cp_closed {
        info!(
            agent = %format!("{}/{}", identity.namespace, identity.name),
            handle,
            "closing connection at the CP's request (registration dropped)"
        );
        let _ = sink.send(Message::Close(None)).await;
    }

    teardown(&state, handle, &identity);
}

/// Announce a fresh registration to the namespace's observers.
fn announce_registration(state: &Arc<AppState>, handle: u64) {
    if let Some(i) = state.registry.get(handle) {
        state.events.emit(
            &state.registry,
            &i.namespace,
            CpEvent::AgentRegistered {
                agent: i.logical_id(),
                agent_type: i.agent_type.clone(),
                instance_id: i.instance_id,
                labels: i.labels,
            },
        );
    }
}

/// Deregister an instance, announce it to the lobby, and fail its in-flight
/// delegations. Shared by socket teardown and lease expiry — the only
/// difference an observer sees is the [`DeregisterReason`].
fn deregister_and_announce(state: &Arc<AppState>, handle: u64, reason: DeregisterReason) {
    if let Some(i) = state.registry.deregister(handle) {
        // Emitted after removal: a dying connection is never a fan-out target.
        state.events.emit(
            &state.registry,
            &i.namespace,
            CpEvent::AgentDeregistered {
                agent: i.logical_id(),
                instance_id: i.instance_id,
                reason,
            },
        );
    }
    let mut next = || state.next_rpc_id();
    for (inst, frame) in
        state
            .router
            .fail_instance(&state.registry, &state.events, handle, &mut next)
    {
        let _ = inst.tx.try_send(frame);
    }
}

/// Deregister this connection's own registration (by handle — cannot touch
/// another connection's entry) and fail its in-flight delegations.
fn teardown(state: &Arc<AppState>, handle: u64, identity: &AgentIdentity) {
    deregister_and_announce(state, handle, DeregisterReason::Disconnect);
    info!(
        agent = %format!("{}/{}", identity.namespace, identity.name),
        handle,
        "disconnected"
    );
}

/// Validate the registration frame against the authenticated identity.
/// Returns the parsed params and the request id, or an error payload.
fn parse_register(
    text: &str,
    identity: &AgentIdentity,
) -> Result<(RegisterParams, u64), (u64, ErrorObject)> {
    let msg: JsonRpcMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            return Err((
                0,
                ErrorObject::new(codes::INVALID_PARAMS, format!("malformed frame: {e}")),
            ))
        }
    };
    let rpc_id = match msg.require_request_envelope() {
        Ok(id) => id,
        Err(err) => return Err((msg.id.unwrap_or(0), err)),
    };
    if msg.method.as_deref() != Some(methods::REGISTER) {
        return Err((
            rpc_id,
            ErrorObject::new(codes::NOT_REGISTERED, "first frame must be cp/register"),
        ));
    }
    let params: RegisterParams = match msg.params.and_then(|p| serde_json::from_value(p).ok()) {
        Some(p) => p,
        None => {
            return Err((
                rpc_id,
                ErrorObject::new(codes::INVALID_PARAMS, "invalid cp/register params"),
            ))
        }
    };
    if params.protocol_version != PROTOCOL_VERSION {
        return Err((
            rpc_id,
            ErrorObject::new(
                codes::UNSUPPORTED_VERSION,
                format!(
                    "protocol version {} unsupported (CP speaks {})",
                    params.protocol_version, PROTOCOL_VERSION
                ),
            ),
        ));
    }
    // Identity binding: claims must match the key's bound identity exactly.
    if params.namespace != identity.namespace
        || params.name != identity.name
        || params.agent_type != identity.agent_type
    {
        return Err((
            rpc_id,
            ErrorObject::new(
                codes::IDENTITY_MISMATCH,
                format!(
                    "registration claims {}/{} ({}) do not match the identity bound to this key",
                    params.namespace, params.name, params.agent_type
                ),
            ),
        ));
    }
    if params.instance_id.trim().is_empty() {
        return Err((
            rpc_id,
            ErrorObject::new(codes::INVALID_PARAMS, "instance_id must be non-empty"),
        ));
    }
    Ok((params, rpc_id))
}

/// Dispatch one post-registration frame. Returns an optional direct reply.
fn handle_frame(state: &Arc<AppState>, handle: u64, text: &str) -> Option<String> {
    let msg: JsonRpcMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            let resp = JsonRpcErrorResponse::new(
                0,
                ErrorObject::new(codes::INVALID_PARAMS, format!("malformed frame: {e}")),
            );
            return Some(serde_json::to_string(&resp).expect("serializable"));
        }
    };
    // Responses to CP-issued requests (forwarded delegates, cancels): v1
    // correlates by delegation_id inside result frames, so plain JSON-RPC
    // acks are dropped.
    let method = msg.method.as_deref()?.to_string();
    let rpc_id = match msg.require_request_envelope() {
        Ok(id) => id,
        Err(err) => {
            let resp = JsonRpcErrorResponse::new(msg.id.unwrap_or(0), err);
            return Some(serde_json::to_string(&resp).expect("serializable"));
        }
    };
    // The sender's identity claims are never read from the frame: everything
    // derives from the authenticated registration behind `handle`.
    let me = state.registry.get(handle)?;

    // Observers are read-only. Policy already denies their delegations and
    // ownership checks drop their results/cancels; rejecting up front turns a
    // silent drop into an actionable error.
    if me.agent_type == AgentType::Observer
        && (method == methods::DELEGATE
            || method == methods::DELEGATE_RESULT
            || method == methods::CANCEL)
    {
        let resp = JsonRpcErrorResponse::new(
            rpc_id,
            ErrorObject::new(
                codes::POLICY_DENIED,
                format!(
                    "{method} is not available to observers: they are read-only \
                     (cp/heartbeat, cp/list_agents, and cp/event only)"
                ),
            ),
        );
        return Some(serde_json::to_string(&resp).expect("serializable"));
    }

    macro_rules! params_or_err {
        ($ty:ty) => {
            match msg
                .params
                .clone()
                .and_then(|p| serde_json::from_value::<$ty>(p).ok())
            {
                Some(p) => p,
                None => {
                    let resp = JsonRpcErrorResponse::new(
                        rpc_id,
                        ErrorObject::new(codes::INVALID_PARAMS, "invalid params"),
                    );
                    return Some(serde_json::to_string(&resp).expect("serializable"));
                }
            }
        };
    }

    match method.as_str() {
        methods::HEARTBEAT => {
            let _p = params_or_err!(crate::proto::HeartbeatParams);
            state.registry.heartbeat(handle);
            let resp = JsonRpcResponse::new(rpc_id, serde_json::json!({"ok": true}));
            Some(serde_json::to_string(&resp).expect("serializable"))
        }
        methods::DELEGATE => {
            let p = params_or_err!(DelegateParams);
            if p.prompt.len() > state.cfg.max_prompt_bytes {
                let resp = JsonRpcErrorResponse::new(
                    rpc_id,
                    ErrorObject::new(
                        codes::INVALID_PARAMS,
                        format!(
                            "prompt exceeds max_prompt_bytes ({})",
                            state.cfg.max_prompt_bytes
                        ),
                    ),
                );
                return Some(serde_json::to_string(&resp).expect("serializable"));
            }
            let outcome = state.router.delegate(
                &state.cfg,
                &state.registry,
                &state.events,
                &me.namespace,
                &me.name,
                &me.agent_type,
                handle,
                p,
                state.next_rpc_id(),
            );
            let reply = match outcome {
                DelegateOutcome::Accepted(ack) => serde_json::to_string(&JsonRpcResponse::new(
                    rpc_id,
                    serde_json::to_value(&ack).expect("serializable"),
                )),
                DelegateOutcome::Rejected(err) => {
                    serde_json::to_string(&JsonRpcErrorResponse::new(rpc_id, err))
                }
            };
            Some(reply.expect("serializable"))
        }
        methods::DELEGATE_RESULT => {
            let p = params_or_err!(DelegateResultParams);
            if let Some((initiator, frame)) = state.router.complete(
                &state.registry,
                &state.events,
                handle,
                p,
                state.cfg.max_result_bytes,
                state.next_rpc_id(),
            ) {
                let _ = initiator.tx.try_send(frame);
            }
            let resp = JsonRpcResponse::new(rpc_id, serde_json::json!({"ok": true}));
            Some(serde_json::to_string(&resp).expect("serializable"))
        }
        methods::CANCEL => {
            let p = params_or_err!(CancelParams);
            match state.router.cancel(
                &state.registry,
                &state.events,
                handle,
                &p,
                state.next_rpc_id(),
            ) {
                Ok(forward) => {
                    if let Some((target, frame)) = forward {
                        let _ = target.tx.try_send(frame);
                    }
                    let resp = JsonRpcResponse::new(rpc_id, serde_json::json!({"ok": true}));
                    Some(serde_json::to_string(&resp).expect("serializable"))
                }
                Err(err) => Some(
                    serde_json::to_string(&JsonRpcErrorResponse::new(rpc_id, err))
                        .expect("serializable"),
                ),
            }
        }
        // Namespace-scoped roster. Open to any registered client (observers
        // included) — the scope is the caller's authenticated namespace, never
        // a frame-supplied one. v1 takes no params, so an absent or empty
        // params object is equally acceptable.
        methods::LIST_AGENTS => {
            let agents: Vec<AgentSummary> = state
                .registry
                .list(&me.namespace)
                .into_iter()
                .map(|i| AgentSummary {
                    name: i.name,
                    agent_type: i.agent_type,
                    instance_id: i.instance_id,
                    labels: i.labels,
                    active_sessions: i.active_sessions,
                    max_delegated_sessions: i.max_delegated_sessions,
                })
                .collect();
            let result = ListAgentsResult {
                namespace: me.namespace.clone(),
                agents,
            };
            let resp =
                JsonRpcResponse::new(rpc_id, serde_json::to_value(&result).expect("serializable"));
            Some(serde_json::to_string(&resp).expect("serializable"))
        }
        other => {
            let resp = JsonRpcErrorResponse::new(
                rpc_id,
                ErrorObject::new(codes::METHOD_NOT_FOUND, format!("unknown method {other}")),
            );
            Some(serde_json::to_string(&resp).expect("serializable"))
        }
    }
}

/// One lease-expiry pass: drop registrations whose lease elapsed, close their
/// connections, and fail their in-flight delegations.
///
/// Signalling the connection is what makes the deregistration complete
/// (review round-3 F1): without it the connection task keeps running against
/// a registration that no longer exists — every later frame (heartbeats
/// included) finds no registry entry and gets no reply, and the client cannot
/// re-register because registration is first-frame-only.
///
/// `lease` is a parameter so tests can sweep with a zero window.
pub fn sweep_leases(state: &Arc<AppState>, lease: Duration) {
    for handle in state.registry.expired(lease) {
        warn!(
            handle,
            "lease expired — deregistering and closing connection"
        );
        // Signal first: `deregister` drops the registry's side of the signal.
        state.registry.signal_shutdown(handle);
        // Removal, the `lease_expired` announcement, and in-flight failure
        // all live in one place, shared with socket teardown.
        deregister_and_announce(state, handle, DeregisterReason::LeaseExpired);
    }
}

/// Background sweeps: lease expiry and delegation deadlines.
pub async fn run_sweeper(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let lease = Duration::from_secs(state.cfg.lease_expiry_secs);
    loop {
        tick.tick().await;

        sweep_leases(&state, lease);

        // Deadline sweep.
        let mut next = || state.next_rpc_id();
        for (inst, frame) in state.router.sweep_deadlines(
            &state.registry,
            &state.events,
            chrono::Utc::now(),
            &mut next,
        ) {
            let _ = inst.tx.try_send(frame);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::AgentType;

    fn identity() -> AgentIdentity {
        AgentIdentity {
            key: "k".into(),
            namespace: "prod".into(),
            name: "koudu".into(),
            agent_type: AgentType::Primary,
            max_delegated_sessions_cap: None,
        }
    }

    #[test]
    fn register_valid() {
        let frame = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "cp/register",
            "params": {
                "protocol_version": 1,
                "namespace": "prod",
                "name": "koudu",
                "type": "primary",
                "instance_id": "i-1"
            }
        })
        .to_string();
        let (params, rpc) = parse_register(&frame, &identity()).unwrap();
        assert_eq!(params.instance_id, "i-1");
        assert_eq!(rpc, 1);
    }

    #[test]
    fn register_identity_mismatch_rejected() {
        for (ns, name, ty) in [
            ("dev", "koudu", "primary"),
            ("prod", "other", "primary"),
            ("prod", "koudu", "worker"),
        ] {
            let frame = serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "cp/register",
                "params": {
                    "protocol_version": 1,
                    "namespace": ns,
                    "name": name,
                    "type": ty,
                    "instance_id": "i-1"
                }
            })
            .to_string();
            let (_, err) = parse_register(&frame, &identity()).unwrap_err();
            assert_eq!(err.code, codes::IDENTITY_MISMATCH, "{ns}/{name}/{ty}");
        }
    }

    #[test]
    fn register_wrong_first_method_rejected() {
        let frame = serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "cp/heartbeat", "params": {"instance_id": "i-1"}
        })
        .to_string();
        let (_, err) = parse_register(&frame, &identity()).unwrap_err();
        assert_eq!(err.code, codes::NOT_REGISTERED);
    }

    #[test]
    fn register_unsupported_version_rejected() {
        let frame = serde_json::json!({
            "jsonrpc": "2.0", "id": 4, "method": "cp/register",
            "params": {
                "protocol_version": 99,
                "namespace": "prod",
                "name": "koudu",
                "type": "primary",
                "instance_id": "i-1"
            }
        })
        .to_string();
        let (_, err) = parse_register(&frame, &identity()).unwrap_err();
        assert_eq!(err.code, codes::UNSUPPORTED_VERSION);
    }

    #[test]
    fn register_empty_instance_id_rejected() {
        let frame = serde_json::json!({
            "jsonrpc": "2.0", "id": 5, "method": "cp/register",
            "params": {
                "protocol_version": 1,
                "namespace": "prod",
                "name": "koudu",
                "type": "primary",
                "instance_id": "  "
            }
        })
        .to_string();
        let (_, err) = parse_register(&frame, &identity()).unwrap_err();
        assert_eq!(err.code, codes::INVALID_PARAMS);
    }

    #[test]
    fn register_invalid_envelope_rejected() {
        // Missing jsonrpc field (review F4).
        let no_ver = serde_json::json!({
            "id": 6, "method": "cp/register",
            "params": {
                "protocol_version": 1,
                "namespace": "prod",
                "name": "koudu",
                "type": "primary",
                "instance_id": "i-1"
            }
        })
        .to_string();
        let (_, err) = parse_register(&no_ver, &identity()).unwrap_err();
        assert_eq!(err.code, codes::INVALID_REQUEST);

        // Notification shape: no id.
        let no_id = serde_json::json!({
            "jsonrpc": "2.0", "method": "cp/register",
            "params": {
                "protocol_version": 1,
                "namespace": "prod",
                "name": "koudu",
                "type": "primary",
                "instance_id": "i-1"
            }
        })
        .to_string();
        let (_, err) = parse_register(&no_id, &identity()).unwrap_err();
        assert_eq!(err.code, codes::INVALID_REQUEST);
    }

    fn state_with(cfg_toml: &str) -> Arc<AppState> {
        let cfg: CpConfig = toml::from_str(cfg_toml).unwrap();
        cfg.validate().unwrap();
        Arc::new(AppState::new(cfg))
    }

    #[test]
    fn conn_quota_bounds_and_recycles_slots() {
        // Review round-3 F4(b): the quota is a hard bound and the guard
        // releases the slot on drop, so no exit path can leak it.
        let state = state_with("max_connections_per_identity = 2");
        let id = identity();
        let p1 = state.try_acquire_conn(&id).expect("slot 1");
        let p2 = state.try_acquire_conn(&id).expect("slot 2");
        assert_eq!(state.conn_count("prod/koudu"), 2);
        assert!(
            state.try_acquire_conn(&id).is_none(),
            "third concurrent connection must be refused"
        );

        drop(p1);
        assert_eq!(state.conn_count("prod/koudu"), 1);
        let p3 = state
            .try_acquire_conn(&id)
            .expect("released slot is reusable");
        drop(p2);
        drop(p3);
        assert_eq!(state.conn_count("prod/koudu"), 0);
        assert!(state.try_acquire_conn(&id).is_some());
    }

    #[test]
    fn conn_quota_is_per_identity() {
        let state = state_with("max_connections_per_identity = 1");
        let a = identity();
        let mut b = identity();
        b.key = "k2".into();
        b.name = "worker-1".into();
        let _pa = state.try_acquire_conn(&a).expect("koudu slot");
        let _pb = state
            .try_acquire_conn(&b)
            .expect("worker-1 has its own quota");
        assert!(
            state.try_acquire_conn(&a).is_none(),
            "quota is per identity, not global"
        );
        assert_eq!(state.conn_count("prod/koudu"), 1);
        assert_eq!(state.conn_count("prod/worker-1"), 1);
    }

    #[tokio::test]
    async fn sweep_leases_signals_the_connection_before_dropping_it() {
        // Review round-3 F1 at the sweeper level: the shutdown signal is
        // delivered, not just the registry entry removed. (The end-to-end
        // proof over a real socket lives in tests/ws_lifecycle.rs.)
        let state = state_with("heartbeat_interval_secs = 1\nlease_expiry_secs = 2");
        let signal = crate::registry::shutdown_signal();
        let mut observer = signal.subscribe();
        let (tx, _rx) = mpsc::channel::<String>(OUTBOUND_QUEUE);
        let handle = state.registry.register_conn(
            Instance {
                handle: 0,
                namespace: "prod".into(),
                name: "koudu".into(),
                agent_type: AgentType::Primary,
                instance_id: "i-1".into(),
                labels: Default::default(),
                max_delegated_sessions: 1,
                active_sessions: 0,
                registered_at: Instant::now(),
                last_heartbeat: Instant::now(),
                tx,
            },
            Arc::clone(&signal),
        );

        // A live lease is left alone.
        sweep_leases(&state, Duration::from_secs(60));
        assert!(state.registry.get(handle).is_some());
        assert!(!*observer.borrow());

        sweep_leases(&state, Duration::ZERO);
        assert!(state.registry.get(handle).is_none());
        observer.changed().await.unwrap();
        assert!(
            *observer.borrow(),
            "the owning connection must be told to close"
        );
    }

    // --- observer / lobby wiring (Phase 1) ---

    fn join(
        state: &Arc<AppState>,
        ns: &str,
        name: &str,
        ty: AgentType,
    ) -> (u64, mpsc::Receiver<String>) {
        join_at(state, ns, name, ty, Instant::now())
    }

    fn join_at(
        state: &Arc<AppState>,
        ns: &str,
        name: &str,
        ty: AgentType,
        last_heartbeat: Instant,
    ) -> (u64, mpsc::Receiver<String>) {
        let (tx, rx) = mpsc::channel(OUTBOUND_QUEUE);
        let handle = state.registry.register(Instance {
            handle: 0,
            namespace: ns.into(),
            name: name.into(),
            agent_type: ty,
            instance_id: format!("i-{name}"),
            labels: Default::default(),
            max_delegated_sessions: 2,
            active_sessions: 0,
            registered_at: Instant::now(),
            last_heartbeat,
            tx,
        });
        (handle, rx)
    }

    fn events_of(rx: &mut mpsc::Receiver<String>) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        while let Ok(text) = rx.try_recv() {
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(v["method"], "cp/event");
            out.push(v["params"].clone());
        }
        out
    }

    fn call(state: &Arc<AppState>, handle: u64, method: &str, params: serde_json::Value) -> String {
        let frame = serde_json::json!({
            "jsonrpc": "2.0", "id": 42, "method": method, "params": params
        })
        .to_string();
        handle_frame(state, handle, &frame).expect("a reply")
    }

    #[test]
    fn registration_is_announced_to_observers_including_other_observers() {
        let state = state_with("");
        let (_, mut lobby) = join(&state, "prod", "lobby", AgentType::Observer);
        let (h_lobby2, mut lobby2) = join(&state, "prod", "lobby-2", AgentType::Observer);
        let (h_worker, _w_rx) = join(&state, "prod", "worker-1", AgentType::Worker);

        // An observer's own arrival is visible to the lobby (itself included).
        announce_registration(&state, h_lobby2);
        announce_registration(&state, h_worker);

        let seen = events_of(&mut lobby);
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0]["event"], "agent_registered");
        assert_eq!(seen[0]["agent"], "prod/lobby-2");
        assert_eq!(seen[0]["type"], "observer");
        assert_eq!(seen[0]["seq"], 1);
        assert_eq!(seen[1]["agent"], "prod/worker-1");
        assert_eq!(seen[1]["type"], "worker");
        assert_eq!(seen[1]["instance_id"], "i-worker-1");
        assert_eq!(seen[1]["seq"], 2);
        assert_eq!(events_of(&mut lobby2).len(), 2);
    }

    #[test]
    fn disconnect_and_lease_expiry_announce_distinct_reasons() {
        let state = state_with("");
        let (_, mut lobby) = join(&state, "prod", "lobby", AgentType::Observer);
        let (h_a, _rx_a) = join(&state, "prod", "worker-a", AgentType::Worker);
        // worker-b stopped heartbeating five minutes ago; the lobby and
        // worker-a are current, so only worker-b's lease is overdue.
        let (h_b, _rx_b) = join_at(
            &state,
            "prod",
            "worker-b",
            AgentType::Worker,
            Instant::now() - std::time::Duration::from_secs(300),
        );

        teardown(&state, h_a, &identity());
        sweep_leases(&state, std::time::Duration::from_secs(60));

        let seen = events_of(&mut lobby);
        assert_eq!(seen.len(), 2, "one disconnect + one lease expiry: {seen:?}");
        assert_eq!(seen[0]["event"], "agent_deregistered");
        assert_eq!(seen[0]["agent"], "prod/worker-a");
        assert_eq!(seen[0]["reason"], "disconnect");
        assert_eq!(seen[0]["seq"], 1);
        assert_eq!(seen[1]["agent"], "prod/worker-b");
        assert_eq!(seen[1]["reason"], "lease_expired");
        assert_eq!(seen[1]["instance_id"], "i-worker-b");
        assert_eq!(seen[1]["seq"], 2);
        assert!(state.registry.get(h_a).is_none());
        assert!(state.registry.get(h_b).is_none());
        assert_eq!(
            state.registry.observers("prod").len(),
            1,
            "the current observer keeps its registration"
        );
    }

    #[test]
    fn list_agents_returns_the_callers_namespace_roster() {
        let state = state_with("");
        let (h_primary, _p) = join(&state, "prod", "koudu", AgentType::Primary);
        let (h_lobby, _l) = join(&state, "prod", "lobby", AgentType::Observer);
        join(&state, "dev", "other", AgentType::Worker);

        for handle in [h_primary, h_lobby] {
            let reply = call(&state, handle, methods::LIST_AGENTS, serde_json::json!({}));
            let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(v["id"], 42);
            assert_eq!(v["result"]["namespace"], "prod");
            let agents = v["result"]["agents"].as_array().unwrap();
            assert_eq!(agents.len(), 2, "dev/other must not leak: {agents:?}");
            let names: Vec<&str> = agents.iter().map(|a| a["name"].as_str().unwrap()).collect();
            assert!(names.contains(&"koudu") && names.contains(&"lobby"));
            let lobby = agents.iter().find(|a| a["name"] == "lobby").unwrap();
            assert_eq!(lobby["type"], "observer");
            assert_eq!(lobby["instance_id"], "i-lobby");
            assert_eq!(lobby["active_sessions"], 0);
            assert_eq!(lobby["max_delegated_sessions"], 2);
        }

        // v1 takes no params: an absent params object is accepted too.
        let frame =
            serde_json::json!({"jsonrpc": "2.0", "id": 7, "method": "cp/list_agents"}).to_string();
        let reply = handle_frame(&state, h_primary, &frame).unwrap();
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["result"]["namespace"], "prod");
    }

    #[test]
    fn observers_are_rejected_from_the_delegation_methods() {
        let state = state_with("");
        let (h_lobby, _l) = join(&state, "prod", "lobby", AgentType::Observer);
        let (h_worker, _w) = join(&state, "prod", "worker-1", AgentType::Worker);

        for (method, params) in [
            (
                methods::DELEGATE,
                serde_json::json!({
                    "delegation_id": "d-1",
                    "target": {"name": "worker-1"},
                    "prompt": "do it",
                    "deadline": (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339()
                }),
            ),
            (
                methods::DELEGATE_RESULT,
                serde_json::json!({"delegation_id": "d-1", "status": "completed"}),
            ),
            (
                methods::CANCEL,
                serde_json::json!({"delegation_id": "d-1", "reason": "no"}),
            ),
        ] {
            let reply = call(&state, h_lobby, method, params);
            let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(
                v["error"]["code"],
                codes::POLICY_DENIED,
                "{method} must be denied for observers: {v}"
            );
            assert!(v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("read-only"));
        }

        // Heartbeat and list_agents remain available to observers.
        let hb = call(
            &state,
            h_lobby,
            methods::HEARTBEAT,
            serde_json::json!({"instance_id": "i-lobby"}),
        );
        assert!(hb.contains("\"ok\":true"));
        // A non-observer is unaffected by the guard.
        let reply = call(
            &state,
            h_worker,
            methods::CANCEL,
            serde_json::json!({"delegation_id": "d-nope", "reason": "x"}),
        );
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        // The router's own refusal for an unknown id is a byte-identical
        // POLICY_DENIED (review round-3 F3), so the code alone cannot tell
        // the two denials apart — the message can: only the guard says
        // "read-only".
        assert_eq!(v["error"]["code"], codes::POLICY_DENIED, "{v}");
        let msg = v["error"]["message"].as_str().unwrap();
        assert!(
            !msg.contains("read-only") && msg.contains("not in flight for this instance"),
            "worker reaches the router, not the observer guard: {msg}"
        );
    }

    #[test]
    fn delegate_through_handle_frame_emits_lobby_events() {
        let state = state_with("");
        let (h_primary, _p) = join(&state, "prod", "koudu", AgentType::Primary);
        let (h_worker, mut w_rx) = join(&state, "prod", "worker-1", AgentType::Worker);
        let (_, mut lobby) = join(&state, "prod", "lobby", AgentType::Observer);

        let reply = call(
            &state,
            h_primary,
            methods::DELEGATE,
            serde_json::json!({
                "delegation_id": "d-1",
                "target": {"name": "worker-1"},
                "prompt": "ship it",
                "deadline": (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339()
            }),
        );
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["result"]["assigned_to"], "prod/worker-1", "{v}");
        assert!(w_rx.try_recv().unwrap().contains("cp/delegate"));

        let reply = call(
            &state,
            h_worker,
            methods::DELEGATE_RESULT,
            serde_json::json!({"delegation_id": "d-1", "status": "completed", "result": "ok"}),
        );
        assert!(reply.contains("\"ok\":true"));

        let seen = events_of(&mut lobby);
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0]["event"], "delegation_requested");
        assert_eq!(seen[0]["prompt_excerpt"], "ship it");
        assert_eq!(seen[1]["event"], "delegation_completed");
        assert_eq!(seen[1]["result_excerpt"], "ok");
        assert_eq!(seen[0]["seq"], 1);
        assert_eq!(seen[1]["seq"], 2);
    }
}
