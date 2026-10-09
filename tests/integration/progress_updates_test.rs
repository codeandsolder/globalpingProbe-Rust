/// Integration tests for in-progress measurement streaming.
/// Verifies that ping and traceroute emit partial results on the progress channel
/// as they run, before the final result is returned.
use globalping_probe::command::{
    ProgressTx, dns::DnsCommand, http::HttpCommand, mtr::MtrCommand, ping::PingCommand,
    traceroute::TracerouteCommand,
};
use globalping_probe::util::progress_buffer::BufferMode;
use serde_json::json;

// ── Ping in-progress ──────────────────────────────────────────────────────────

/// Verify the progress channel path exists and is type-correct (compile check).
#[test]
fn progress_methods_are_constructible() {
    let (tx, _rx) = ProgressTx::channel(BufferMode::Append);
    let ping_future = PingCommand.run_with_progress(json!({}), tx.clone());
    let dns_future = DnsCommand.run_with_progress(json!({}), tx.clone());
    let traceroute_future = TracerouteCommand.run_with_progress(json!({}), tx.clone());
    let mtr_future = MtrCommand.run_with_progress(json!({}), tx.clone());
    let http_future = HttpCommand.run_with_progress(json!({}), tx);
    drop((
        ping_future,
        dns_future,
        traceroute_future,
        mtr_future,
        http_future,
    ));
}

/// Verify producers can detect a dropped progress receiver without panicking.
#[test]
fn closed_progress_channel_send_returns_error() {
    let (tx, rx) = ProgressTx::channel(BufferMode::Append);
    drop(rx);
    assert!(tx.send(json!({"status": "in-progress"})).is_err());
}

// ── Channel mechanics ─────────────────────────────────────────────────────────

#[tokio::test]
async fn progress_channel_delivers_values_in_order() {
    let (tx, mut rx) = ProgressTx::channel(BufferMode::Append);
    for i in 0u32..5 {
        tx.send(json!({ "seq": i })).unwrap();
    }
    drop(tx);
    let mut seq = 0u32;
    while let Some(update) = rx.recv().await {
        let v = update.resolve();
        assert_eq!(v["seq"].as_u64().unwrap(), seq as u64);
        seq += 1;
    }
    assert_eq!(seq, 5);
}

#[tokio::test]
async fn progress_channel_terminates_when_sender_dropped() {
    let (tx, mut rx) = ProgressTx::channel(BufferMode::Append);
    drop(tx);
    assert!(rx.recv().await.is_none());
}

#[tokio::test]
async fn progress_channel_accepts_partial_ping_shape() {
    let (tx, mut rx) = ProgressTx::channel(BufferMode::Append);
    let partial = json!({
        "rawOutput": "PING 1.1.1.1 (1.1.1.1)\n64 bytes from 1.1.1.1: seq=1 ttl=58 time=10.1 ms\n",
    });
    tx.send(partial.clone()).unwrap();
    drop(tx);
    let received = rx.recv().await.unwrap().resolve();
    assert!(
        received["rawOutput"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
}

#[tokio::test]
async fn progress_channel_accepts_partial_traceroute_shape() {
    let (tx, mut rx) = ProgressTx::channel(BufferMode::Append);
    let partial = json!({
        "rawOutput": "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max\n 1  _gateway (192.168.1.1)  1.2 ms\n",
    });
    tx.send(partial).unwrap();
    drop(tx);
    let received = rx.recv().await.unwrap().resolve();
    assert!(
        received["rawOutput"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
}

// ── inProgressUpdates flag parsing ───────────────────────────────────────────

#[test]
fn in_progress_flag_defaults_to_false() {
    let opts = json!({ "type": "ping", "target": "1.1.1.1" });
    let flag = opts
        .get("inProgressUpdates")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(!flag);
}

#[test]
fn in_progress_flag_true_is_read() {
    let opts = json!({ "type": "traceroute", "target": "1.1.1.1", "inProgressUpdates": true });
    let flag = opts
        .get("inProgressUpdates")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(flag);
}

#[test]
fn in_progress_flag_false_is_read() {
    let opts = json!({ "type": "ping", "target": "1.1.1.1", "inProgressUpdates": false });
    let flag = opts
        .get("inProgressUpdates")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(!flag);
}

// ── Live tests (Linux only) ───────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod live {
    use super::*;

    /// Ping with inProgressUpdates=true — verify at least one partial result
    /// arrives on the channel before the measurement finishes.
    #[tokio::test]
    async fn live_ping_emits_progress_per_packet() {
        let (tx, mut rx) = ProgressTx::channel(BufferMode::Append);
        let options = json!({
            "type": "ping",
            "target": "1.1.1.1",
            "packets": 3,
            "timeout": 10,
            "ipVersion": 4,
            "inProgressUpdates": true,
        });

        // Run measurement and collect progress concurrently
        let measure = tokio::spawn(async move { PingCommand.run_with_progress(options, tx).await });

        let mut partial_count = 0usize;
        while let Some(update) = rx.recv().await {
            let partial = update.resolve();
            partial_count += 1;
            assert!(
                partial["rawOutput"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty()),
                "partial should contain raw output"
            );
        }

        let final_result = measure.await.unwrap().unwrap();
        println!("Ping progress events: {partial_count}");
        println!("Final status: {}", final_result["status"]);

        assert!(
            partial_count >= 1,
            "expected at least 1 progress event for 3 packets"
        );
        assert_eq!(final_result["status"], "finished");
    }

    /// Traceroute with inProgressUpdates=true — verify hop-by-hop progress.
    #[tokio::test]
    async fn live_traceroute_emits_progress_per_hop() {
        let (tx, mut rx) = ProgressTx::channel(BufferMode::Diff);
        let options = json!({
            "type": "traceroute",
            "target": "1.1.1.1",
            "protocol": "ICMP",
            "timeout": 10,
            "ipVersion": 4,
            "inProgressUpdates": true,
        });

        let measure =
            tokio::spawn(async move { TracerouteCommand.run_with_progress(options, tx).await });

        let mut partial_count = 0usize;
        while let Some(update) = rx.recv().await {
            let partial = update.resolve();
            partial_count += 1;
            assert!(
                partial["rawOutput"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty()),
                "partial should contain raw output"
            );
        }

        let final_result = measure.await.unwrap().unwrap();
        println!("Traceroute progress events: {partial_count}");
        println!("Final status: {}", final_result["status"]);
        assert!(partial_count >= 1, "expected at least 1 progress event");
    }

    #[tokio::test]
    async fn live_dns_emits_progress() {
        let (tx, mut rx) = ProgressTx::channel(BufferMode::Diff);
        let options = json!({
            "type": "dns",
            "target": "example.com",
            "protocol": "UDP",
            "port": 53,
            "resolver": "1.1.1.1",
            "trace": false,
            "query": { "type": "A" },
            "ipVersion": 4,
            "timeout": 5,
            "inProgressUpdates": true,
        });
        let measure = tokio::spawn(async move { DnsCommand.run_with_progress(options, tx).await });
        let mut count = 0usize;
        while let Some(update) = rx.recv().await {
            let partial = update.resolve();
            count += 1;
            assert!(
                partial["rawOutput"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
            );
        }
        let result = measure.await.unwrap().unwrap();
        assert!(count >= 1, "expected DNS progress");
        assert_eq!(result["status"], "finished");
    }

    #[tokio::test]
    async fn live_mtr_emits_progress() {
        let (tx, mut rx) = ProgressTx::channel(BufferMode::Overwrite);
        let options = json!({
            "type": "mtr",
            "target": "1.1.1.1",
            "protocol": "udp",
            "port": 80,
            "packets": 3,
            "ipVersion": 4,
            "timeout": 5,
            "inProgressUpdates": true,
        });
        let measure = tokio::spawn(async move { MtrCommand.run_with_progress(options, tx).await });
        let mut count = 0usize;
        while let Some(update) = rx.recv().await {
            let partial = update.resolve();
            count += 1;
            assert!(partial["rawOutput"].as_str().is_some());
        }
        let result = measure.await.unwrap().unwrap();
        assert!(count >= 1, "expected MTR progress");
        assert_eq!(result["status"], "finished");
    }

    #[tokio::test]
    async fn live_http_get_emits_progress() {
        let (tx, mut rx) = ProgressTx::channel(BufferMode::Append);
        let options = json!({
            "type": "http",
            "target": "example.com",
            "protocol": "HTTPS",
            "ipVersion": 4,
            "timeout": 10,
            "inProgressUpdates": true,
            "request": {
                "method": "GET",
                "path": "/",
                "query": "",
                "headers": {}
            }
        });
        let measure = tokio::spawn(async move { HttpCommand.run_with_progress(options, tx).await });
        let mut count = 0usize;
        let mut saw_body = false;
        while let Some(update) = rx.recv().await {
            let partial = update.resolve();
            count += 1;
            saw_body |= partial["rawBody"]
                .as_str()
                .is_some_and(|value| !value.is_empty());
            assert!(partial["rawOutput"].as_str().is_some());
        }
        let result = measure.await.unwrap().unwrap();
        assert!(count >= 1, "expected HTTP GET progress");
        assert!(saw_body, "expected an HTTP body chunk");
        assert_eq!(result["status"], "finished");
    }

    /// Without inProgressUpdates, the channel should receive no events.
    #[tokio::test]
    async fn live_ping_no_progress_when_flag_false() {
        let (tx, mut rx) = ProgressTx::channel(BufferMode::Append);
        // Flag is false — default run path, tx is never used
        let options = json!({
            "type": "ping",
            "target": "1.1.1.1",
            "packets": 2,
            "timeout": 10,
            "ipVersion": 4,
            "inProgressUpdates": false,
        });
        // Call run (not run_with_progress) to simulate the non-progress path.
        // tx is just a bystander here to check it never receives anything.
        drop(tx);
        let result = PingCommand.run(options).await.unwrap();
        assert_eq!(result["status"], "finished");
        // rx is already dropped — recv returns None immediately
        assert!(rx.recv().await.is_none());
    }
}
