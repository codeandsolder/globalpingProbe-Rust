//! Engine.IO v4 / Socket.IO v5 wire session for the probe's JSON-only,
//! WebSocket-only /probes namespace. The application owns reconnection.
use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{Context as _, Result, bail, ensure};
use futures_util::SinkExt as _;
use serde::Deserialize;
use serde_json::Value;
use tokio::{
    sync::{Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, sleep_until, timeout},
};
use url::Url;
use wreq::{
    Client, Version,
    redirect::Policy,
    ws::{WebSocket, message::Message},
};

const NAMESPACE: &str = "/probes";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const ACK_TIMEOUT: Duration = Duration::from_secs(60);
const CHANNEL_CAPACITY: usize = 128;

#[derive(Debug)]
pub struct ConnectRejected(pub Value);

impl std::fmt::Display for ConnectRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Socket.IO namespace rejected: {}", self.0)
    }
}

impl std::error::Error for ConnectRejected {}

#[derive(Clone, Debug)]
pub enum Disconnect {
    PingTimeout,
    TransportError(String),
    TransportClosed,
    ServerDisconnected,
    ServerError(Value),
    ClientDisconnected,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Event {
    pub name: String,
    pub arguments: Vec<Value>,
}

enum Packet {
    Ping(String),
    Open(Open),
    Connected,
    Event(Event),
    Ack { id: u64, arguments: Vec<Value> },
    Rejected(Value),
    NamespaceClose,
    EngineClose,
    Ignored,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Open {
    sid: String,
    ping_interval: u64,
    ping_timeout: u64,
}

struct Heartbeat {
    window: Duration,
    deadline: Instant,
}

impl Heartbeat {
    fn new(open: &Open) -> Result<Self> {
        ensure!(!open.sid.is_empty(), "empty Engine.IO session ID");
        ensure!(
            open.ping_interval > 0 && open.ping_timeout > 0,
            "invalid heartbeat"
        );
        let window = Duration::from_millis(open.ping_interval)
            .checked_add(Duration::from_millis(open.ping_timeout))
            .context("heartbeat duration overflow")?;
        Ok(Self {
            window,
            deadline: Instant::now()
                .checked_add(window)
                .context("heartbeat deadline overflow")?,
        })
    }

    fn ping(&mut self) -> Result<()> {
        self.deadline = Instant::now()
            .checked_add(self.window)
            .context("heartbeat deadline overflow")?;
        Ok(())
    }
}

fn endpoint(base: &str) -> Result<Url> {
    let mut url = Url::parse(base)?;
    let scheme = match url.scheme() {
        "http" | "ws" => "ws",
        "https" | "wss" => "wss",
        _ => bail!("unsupported probe socket URL scheme"),
    };
    ensure!(
        url.set_scheme(scheme).is_ok(),
        "invalid WebSocket URL scheme"
    );
    ensure!(
        url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "invalid probe socket URL"
    );
    if url.path() == "/" {
        url.set_path("/socket.io/");
    }
    let pairs = url
        .query_pairs()
        .into_owned()
        .filter(|(key, _)| key != "EIO" && key != "transport" && key != "sid")
        .collect::<Vec<_>>();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(pairs)
        .append_pair("EIO", "4")
        .append_pair("transport", "websocket");
    Ok(url)
}

fn parse_packet(text: &str) -> Result<Packet> {
    let (kind, body) = text
        .split_at_checked(1)
        .context("empty or invalid Engine.IO packet")?;
    match kind {
        "0" => Ok(Packet::Open(serde_json::from_str(body)?)),
        "1" if body.is_empty() => Ok(Packet::EngineClose),
        "2" => Ok(Packet::Ping(body.to_owned())),
        "3" | "6" => Ok(Packet::Ignored),
        "4" => parse_namespace_packet(body),
        _ => bail!("unsupported Engine.IO packet type"),
    }
}

fn parse_namespace_packet(text: &str) -> Result<Packet> {
    let (kind, body) = text
        .split_at_checked(1)
        .context("missing Socket.IO packet type")?;
    let (namespace, data) = body
        .split_once(',')
        .context("missing Socket.IO namespace")?;
    ensure!(namespace == NAMESPACE, "unexpected Socket.IO namespace");
    match kind {
        "0" => {
            let data: Value = serde_json::from_str(data)?;
            ensure!(
                data.get("sid")
                    .and_then(Value::as_str)
                    .is_some_and(|sid| !sid.is_empty()),
                "missing Socket.IO session ID"
            );
            Ok(Packet::Connected)
        }
        "1" if data.is_empty() => Ok(Packet::NamespaceClose),
        "2" => {
            // An optional acknowledgement ID precedes the JSON array. Probe
            // events are fire-and-forget; their response is a named event.
            let data = data.trim_start_matches(|character: char| character.is_ascii_digit());
            let mut values = serde_json::from_str::<Vec<Value>>(data)?.into_iter();
            let Some(Value::String(name)) = values.next() else {
                bail!("Socket.IO event is missing its name");
            };
            ensure!(!name.is_empty(), "empty Socket.IO event name");
            Ok(Packet::Event(Event {
                name,
                arguments: values.collect(),
            }))
        }
        "3" => {
            let offset = data
                .find('[')
                .context("missing acknowledgement arguments")?;
            let id = data[..offset].parse()?;
            let arguments = serde_json::from_str(&data[offset..])?;
            Ok(Packet::Ack { id, arguments })
        }
        "4" => Ok(Packet::Rejected(serde_json::from_str(data)?)),
        "5" | "6" => bail!("binary Socket.IO attachments are not part of the probe JSON protocol"),
        _ => bail!("unsupported Socket.IO packet type"),
    }
}

fn encode_event(name: &str, value: Value, id: Option<u64>) -> Result<String> {
    let data = serde_json::to_string(&(name, value))?;
    Ok(id.map_or_else(
        || format!("42{NAMESPACE},{data}"),
        |id| format!("42{NAMESPACE},{id}{data}"),
    ))
}

async fn write_message(socket: &mut WebSocket, message: Message) -> Result<()> {
    timeout(WRITE_TIMEOUT, socket.send(message))
        .await
        .context("WebSocket write timed out")??;
    Ok(())
}

async fn write_text(socket: &mut WebSocket, text: impl Into<String>) -> Result<()> {
    write_message(socket, Message::text(text.into())).await
}

async fn read_packet(socket: &mut WebSocket) -> Result<Packet> {
    loop {
        let Some(message) = socket.recv().await else {
            return Ok(Packet::EngineClose);
        };
        match message? {
            Message::Text(text) => return parse_packet(text.as_str()),
            Message::Ping(_) => {
                // Tungstenite queues the RFC 6455 pong; flush it even if no
                // application message is currently being sent.
                timeout(WRITE_TIMEOUT, socket.flush())
                    .await
                    .context("WebSocket pong timed out")??;
            }
            Message::Pong(_) => {}
            Message::Close(_) => return Ok(Packet::EngineClose),
            Message::Binary(_) => bail!("unexpected binary WebSocket message"),
        }
    }
}

async fn handshake(client: &Client, url: &Url) -> Result<(WebSocket, Heartbeat)> {
    let mut socket = client
        .websocket(url.as_str())
        .version(Version::HTTP_11)
        .send()
        .await?
        .into_websocket()
        .await?;
    let Packet::Open(open) = read_packet(&mut socket).await? else {
        bail!("expected Engine.IO open packet");
    };
    let mut heartbeat = Heartbeat::new(&open)?;
    write_text(&mut socket, format!("40{NAMESPACE},")).await?;
    loop {
        let packet = timeout(
            heartbeat.deadline.saturating_duration_since(Instant::now()),
            read_packet(&mut socket),
        )
        .await
        .context("Engine.IO heartbeat expired during namespace handshake")??;
        match packet {
            Packet::Connected => return Ok((socket, heartbeat)),
            Packet::Rejected(value) => return Err(ConnectRejected(value).into()),
            Packet::Ping(data) => {
                heartbeat.ping()?;
                write_text(&mut socket, format!("3{data}")).await?;
            }
            Packet::Ignored => {}
            _ => bail!("unexpected packet before Socket.IO namespace connection"),
        }
    }
}

type AckCompletion = oneshot::Sender<Result<Vec<Value>, String>>;

enum Delivery {
    Written(oneshot::Sender<Result<(), String>>),
    Acknowledged(AckCompletion),
}

enum Command {
    Emit {
        name: String,
        value: Value,
        delivery: Delivery,
    },
    Close,
}

#[derive(Clone, Debug)]
pub struct EventSender {
    commands: mpsc::Sender<Command>,
    ack_slots: Arc<Semaphore>,
}

impl EventSender {
    async fn request<T>(
        &self,
        name: &str,
        value: Value,
        delivery: Delivery,
        response: oneshot::Receiver<Result<T, String>>,
    ) -> Result<T> {
        self.commands
            .send(Command::Emit {
                name: name.to_owned(),
                value,
                delivery,
            })
            .await
            .context("probe socket is disconnected")?;
        response
            .await
            .context("probe socket closed before event delivery")?
            .map_err(anyhow::Error::msg)
    }

    pub async fn emit(&self, name: &str, value: Value) -> Result<()> {
        let (completion, response) = oneshot::channel();
        timeout(
            WRITE_TIMEOUT,
            self.request(name, value, Delivery::Written(completion), response),
        )
        .await
        .context("probe socket event write timed out")?
    }

    pub async fn emit_with_ack(&self, name: &str, value: Value) -> Result<Vec<Value>> {
        timeout(ACK_TIMEOUT, async {
            let _slot = self.ack_slots.acquire().await?;
            let (completion, response) = oneshot::channel();
            self.request(name, value, Delivery::Acknowledged(completion), response)
                .await
        })
        .await
        .context("probe socket acknowledgement timed out")?
    }
}

#[derive(Default)]
struct Acknowledgements {
    next_id: u64,
    pending: HashMap<u64, AckCompletion>,
}

impl Acknowledgements {
    async fn emit(
        &mut self,
        socket: &mut WebSocket,
        name: &str,
        value: Value,
        delivery: Delivery,
    ) -> Result<()> {
        match delivery {
            Delivery::Written(completion) => {
                if completion.is_closed() {
                    return Ok(());
                }
                let result = write_text(socket, encode_event(name, value, None)?).await;
                let _ = completion.send(
                    result
                        .as_ref()
                        .map_err(|error| format!("{error:#}"))
                        .copied(),
                );
                result
            }
            Delivery::Acknowledged(completion) => {
                if completion.is_closed() {
                    return Ok(());
                }
                self.pending.retain(|_, response| !response.is_closed());
                let id = self.next_id;
                self.next_id = id
                    .checked_add(1)
                    .context("Socket.IO acknowledgement ID exhausted")?;
                let result = write_text(socket, encode_event(name, value, Some(id))?).await;
                match result {
                    Ok(()) => {
                        self.pending.insert(id, completion);
                        Ok(())
                    }
                    Err(error) => {
                        let _ = completion.send(Err(format!("{error:#}")));
                        Err(error)
                    }
                }
            }
        }
    }

    fn complete(&mut self, id: u64, arguments: Vec<Value>) {
        if let Some(completion) = self.pending.remove(&id) {
            let _ = completion.send(Ok(arguments));
        } else {
            tracing::debug!(target: "api-connection", id, "Ignoring late or unknown acknowledgement");
        }
    }
}

pub struct Session {
    sender: EventSender,
    incoming: mpsc::Receiver<Event>,
    closed: watch::Receiver<Option<Disconnect>>,
    task: JoinHandle<()>,
}

impl Session {
    pub async fn connect(base: &str) -> Result<Self> {
        let url = endpoint(base)?;
        let client = Client::builder()
            .connect_timeout(HANDSHAKE_TIMEOUT)
            .redirect(Policy::none())
            .build()?;
        Self::connect_with(&client, &url).await
    }

    async fn connect_with(client: &Client, url: &Url) -> Result<Self> {
        let (socket, heartbeat) = timeout(HANDSHAKE_TIMEOUT, handshake(client, url))
            .await
            .context("Socket.IO handshake timed out")??;
        let (commands_tx, commands_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (incoming_tx, incoming) = mpsc::channel(CHANNEL_CAPACITY);
        let (closed_tx, closed) = watch::channel(None);
        let task = tokio::spawn(async move {
            let reason = run_io(socket, heartbeat, commands_rx, incoming_tx).await;
            closed_tx.send_replace(Some(reason));
        });
        Ok(Self {
            sender: EventSender {
                commands: commands_tx,
                ack_slots: Arc::new(Semaphore::new(CHANNEL_CAPACITY)),
            },
            incoming,
            closed,
            task,
        })
    }

    pub fn sender(&self) -> EventSender {
        self.sender.clone()
    }

    pub fn closed(&self) -> watch::Receiver<Option<Disconnect>> {
        self.closed.clone()
    }

    pub async fn recv(&mut self) -> Option<Event> {
        self.incoming.recv().await
    }

    pub fn stop_receiving(&mut self) {
        self.incoming.close();
    }

    pub async fn disconnect(mut self) {
        self.stop_receiving();
        // Keep the connection alive during application drain; only this
        // explicit command closes the namespace and Engine.IO transport.
        if timeout(WRITE_TIMEOUT, async {
            let _ = self.sender.commands.send(Command::Close).await;
            if let Err(error) = (&mut self.task).await {
                tracing::warn!(target: "api-connection", "Socket I/O task failed: {error}");
            }
        })
        .await
        .is_err()
        {
            tracing::warn!(target: "api-connection", "Socket close timed out");
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn wait_closed(mut closed: watch::Receiver<Option<Disconnect>>) -> Disconnect {
    closed.wait_for(Option::is_some).await.map_or_else(
        |_| Disconnect::TransportError("socket I/O task stopped unexpectedly".to_owned()),
        |reason| {
            reason.clone().unwrap_or_else(|| {
                Disconnect::TransportError("socket closed without a reason".to_owned())
            })
        },
    )
}

fn transport_error(error: &anyhow::Error) -> Disconnect {
    Disconnect::TransportError(format!("{error:#}"))
}

async fn run_io(
    mut socket: WebSocket,
    mut heartbeat: Heartbeat,
    mut commands: mpsc::Receiver<Command>,
    incoming: mpsc::Sender<Event>,
) -> Disconnect {
    let mut acknowledgements = Acknowledgements::default();
    loop {
        tokio::select! {
            () = sleep_until(heartbeat.deadline) => return Disconnect::PingTimeout,
            command = commands.recv() => {
                match command {
                    Some(Command::Emit { name, value, delivery }) => {
                        if let Err(error) = acknowledgements.emit(&mut socket, &name, value, delivery).await {
                            return transport_error(&error);
                        }
                    }
                    Some(Command::Close) => {
                        if let Err(error) = write_text(&mut socket, format!("41{NAMESPACE},")).await {
                            return transport_error(&error);
                        }
                        if let Err(error) = write_text(&mut socket, "1").await {
                            return transport_error(&error);
                        }
                        let _ = write_message(&mut socket, Message::Close(None)).await;
                        return Disconnect::ClientDisconnected;
                    }
                    None => return Disconnect::ClientDisconnected,
                }
            }
            packet = read_packet(&mut socket) => {
                let packet = match packet {
                    Ok(packet) => packet,
                    Err(error) => return transport_error(&error),
                };
                match packet {
                    Packet::Ping(data) => {
                        if let Err(error) = heartbeat.ping() { return transport_error(&error); }
                        if let Err(error) = write_text(&mut socket, format!("3{data}")).await { return transport_error(&error); }
                    }
                    Packet::Event(event) => match incoming.try_send(event) {
                        Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {},
                        Err(mpsc::error::TrySendError::Full(_)) => return Disconnect::TransportError("probe event receiver is overloaded".to_owned()),
                    },
                    Packet::Ack { id, arguments } => acknowledgements.complete(id, arguments),
                    Packet::NamespaceClose => return Disconnect::ServerDisconnected,
                    Packet::EngineClose => return Disconnect::TransportClosed,
                    Packet::Rejected(value) => return Disconnect::ServerError(value),
                    Packet::Ignored => {},
                    Packet::Open(_) | Packet::Connected => return Disconnect::TransportError("unexpected duplicate socket handshake".to_owned()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt as _;
    use serde_json::json;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message as ServerMessage};

    type ServerSocket = WebSocketStream<TcpStream>;

    async fn server_send(socket: &mut ServerSocket, text: &str) -> Result<()> {
        socket.send(ServerMessage::Text(text.into())).await?;
        Ok(())
    }

    async fn server_text(socket: &mut ServerSocket) -> Result<String> {
        match socket.next().await.context("client closed")?? {
            ServerMessage::Text(text) => Ok(text.to_string()),
            other => bail!("expected text, got {other:?}"),
        }
    }

    async fn accept(listener: TcpListener, interval: u64, timeout: u64) -> Result<ServerSocket> {
        let (tcp, _) = listener.accept().await?;
        let mut socket = accept_async(tcp).await?;
        server_send(&mut socket, &format!("0{}", json!({"sid":"engine","upgrades":[],"pingInterval":interval,"pingTimeout":timeout,"maxPayload":1000000}))).await?;
        assert_eq!(server_text(&mut socket).await?, "40/probes,");
        Ok(socket)
    }

    #[test]
    fn wire_endpoint_and_events() -> Result<()> {
        let url = endpoint("https://example.com?uuid=a%26b&EIO=3&transport=polling")?;
        assert_eq!(
            url.as_str(),
            "wss://example.com/socket.io/?uuid=a%26b&EIO=4&transport=websocket"
        );
        assert_eq!(endpoint("http://localhost:1234/custom")?.path(), "/custom");
        assert!(endpoint("ftp://example.com").is_err());
        assert_eq!(
            encode_event("probe:alt-ips", json!([["ip", "token"]]), None)?,
            r#"42/probes,["probe:alt-ips",[["ip","token"]]]"#
        );
        let Packet::Event(event) = parse_packet(r#"42/probes,17["job",{"a":1},true]"#)? else {
            bail!("expected event");
        };
        assert_eq!(
            event,
            Event {
                name: "job".to_owned(),
                arguments: vec![json!({"a":1}), json!(true)]
            }
        );
        for invalid in [
            "",
            "é",
            "42/",
            "42/other,[\"x\"]",
            "42/probes,{}",
            "42/probes,[1]",
            "45/probes,[]",
        ] {
            assert!(parse_packet(invalid).is_err(), "{invalid}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn websocket_handshake_heartbeat_events_and_disconnect() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let (heartbeat_tx, heartbeat_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut socket = accept(listener, 1000, 1000).await?;
            server_send(&mut socket, "2").await?;
            assert_eq!(server_text(&mut socket).await?, "3");
            server_send(&mut socket, r#"40/probes,{"sid":"namespace"}"#).await?;
            server_send(&mut socket, r#"42/probes,["api:settings:update",{"a":1}]"#).await?;
            assert_eq!(
                server_text(&mut socket).await?,
                r#"42/probes,["probe:status:update","ready"]"#
            );
            server_send(&mut socket, "2heartbeat").await?;
            assert_eq!(server_text(&mut socket).await?, "3heartbeat");
            heartbeat_tx
                .send(())
                .map_err(|()| anyhow::anyhow!("heartbeat receiver dropped"))?;
            assert_eq!(server_text(&mut socket).await?, "41/probes,");
            assert_eq!(server_text(&mut socket).await?, "1");
            Ok::<_, anyhow::Error>(())
        });
        timeout(Duration::from_secs(5), async {
            let mut session = Session::connect(&base).await?;
            let event = session.recv().await.context("missing event")?;
            assert_eq!(event.name, "api:settings:update");
            assert_eq!(event.arguments, vec![json!({"a":1})]);
            session
                .sender()
                .emit("probe:status:update", json!("ready"))
                .await?;
            heartbeat_rx.await?;
            session.disconnect().await;
            server.await??;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }

    #[tokio::test]
    async fn acknowledgements_are_correlated_out_of_order() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let mut socket = accept(listener, 1000, 1000).await?;
            server_send(&mut socket, r#"40/probes,{"sid":"namespace"}"#).await?;
            let first = server_text(&mut socket).await?;
            let second = server_text(&mut socket).await?;
            for packet in [&second, &first] {
                let body = packet.strip_prefix("42/probes,").context("event prefix")?;
                let (id, args) = body.split_at(body.find('[').context("event arguments")?);
                let args: Vec<Value> = serde_json::from_str(args)?;
                server_send(&mut socket, &format!("43/probes,{id}{}", json!([args[1]]))).await?;
            }
            server_text(&mut socket).await?;
            server_send(&mut socket, "41/probes,").await?;
            Ok::<_, anyhow::Error>(())
        });
        timeout(Duration::from_secs(5), async {
            let session = Session::connect(&base).await?;
            let sender = session.sender();
            let (a, b) = tokio::join!(
                sender.emit_with_ack("a", json!(1)),
                sender.emit_with_ack("b", json!(2))
            );
            assert_eq!(a?, vec![json!(1)]);
            assert_eq!(b?, vec![json!(2)]);
            assert!(sender.emit_with_ack("pending", Value::Null).await.is_err());
            server.await??;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }

    #[tokio::test]
    async fn rejection_and_heartbeat_timeout_are_distinct() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let mut socket = accept(listener, 1000, 1000).await?;
            server_send(
                &mut socket,
                r#"44/probes,{"message":"ip limit","data":{"ipAddress":"192.0.2.1"}}"#,
            )
            .await?;
            Ok::<_, anyhow::Error>(())
        });
        let result = Session::connect(&base).await;
        let Err(error) = result else {
            bail!("namespace should reject");
        };
        assert_eq!(
            error
                .downcast_ref::<ConnectRejected>()
                .context("missing rejection")?
                .0["message"],
            "ip limit"
        );
        server.await??;

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let mut socket = accept(listener, 150, 150).await?;
            server_send(&mut socket, r#"40/probes,{"sid":"namespace"}"#).await?;
            tokio::time::sleep(Duration::from_millis(700)).await;
            Ok::<_, anyhow::Error>(())
        });
        let session = Session::connect(&base).await?;
        let reason = timeout(Duration::from_secs(2), wait_closed(session.closed())).await?;
        assert!(matches!(reason, Disconnect::PingTimeout));
        assert!(session.sender().emit("late", Value::Null).await.is_err());
        server.await??;
        Ok(())
    }
}
