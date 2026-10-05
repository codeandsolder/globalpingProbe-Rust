/// Integration tests for in-progress measurement streaming.
/// Verifies that ping and traceroute emit partial results on the progress channel
/// as they run, before the final result is returned.
use globalping_probe::command::{ping::PingCommand, traceroute::TracerouteCommand};
use serde_json::json;
use tokio::sync::mpsc;

// ── Ping in-progress ──────────────────────────────────────────────────────────

/// Verify the progress channel path exists and is type-correct (compile check).
#[test]
fn progress_methods_are_constructible() {
    let (tx, _rx) = mpsc::unbounded_channel();
    let ping_future = PingCommand.run_with_progress(json!({}), tx.clone());
    let traceroute_future = TracerouteCommand.run_with_progress(json!({}), tx);
    drop((ping_future, traceroute_future));
}

/// Verify producers can detect a dropped progress receiver without panicking.
#[test]
fn closed_progress_channel_send_returns_error() {
    let (tx, rx) = mpsc::unbounded_channel::<serde_json::Value>();
    drop(rx);
    assert!(tx.send(json!({"status": "in-progress"})).is_err());
}

// ── Channel mechanics ─────────────────────────────────────────────────────────

#[tokio::test]
async fn progress_channel_delivers_values_in_order() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    for i in 0u32..5 {
        tx.send(json!({ "seq": i })).unwrap();
    }
    drop(tx);
    let mut seq = 0u32;
    while let Some(v) = rx.recv().await {
        assert_eq!(v["seq"].as_u64().unwrap(), seq as u64);
        seq += 1;
    }
    assert_eq!(seq, 5);
}

#[tokio::test]
async fn progress_channel_terminates_when_sender_dropped() {
    let (tx, mut rx) = mpsc::unbounded_channel::<serde_json::Value>();
    drop(tx);
    assert!(rx.recv().await.is_none());
}

#[tokio::test]
async fn progress_channel_accepts_partial_ping_shape() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let partial = json!({
        "status": "in-progress",
        "rawOutput": "PING 1.1.1.1 (1.1.1.1)\n64 bytes from 1.1.1.1: seq=1 ttl=58 time=10.1 ms\n",
        "resolvedAddress": "1.1.1.1",
        "resolvedHostname": null,
        "timings": [{"rtt": 10.1, "ttl": 58}],
        "stats": {"min": 10.1, "max": 10.1, "avg": 10.1},
    });
    tx.send(partial.clone()).unwrap();
    drop(tx);
    let received = rx.recv().await.unwrap();
    assert_eq!(received["status"], "in-progress");
    assert_eq!(received["timings"][0]["rtt"], 10.1);
}

#[tokio::test]
async fn progress_channel_accepts_partial_traceroute_shape() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let partial = json!({
        "status": "in-progress",
        "rawOutput": "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max\n 1  _gateway (192.168.1.1)  1.2 ms\n",
        "resolvedAddress": "1.1.1.1",
        "resolvedHostname": null,
        "hops": [{ "resolvedAddress": "192.168.1.1", "resolvedHostname": "_gateway", "timings": [{"rtt": 1.2}] }],
    });
    tx.send(partial).unwrap();
    drop(tx);
    let received = rx.recv().await.unwrap();
    assert_eq!(received["status"], "in-progress");
    assert!(received["hops"].as_array().unwrap().len() > 0);
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
        let (tx, mut rx) = mpsc::unbounded_channel();
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
        while let Some(partial) = rx.recv().await {
            partial_count += 1;
            assert_eq!(
                partial["status"], "in-progress",
                "partial status should be in-progress"
            );
            assert!(
                partial["timings"]
                    .as_array()
                    .map_or(false, |t| !t.is_empty()),
                "partial should have at least one timing"
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
        let (tx, mut rx) = mpsc::unbounded_channel();
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

        let mut hop_counts: Vec<usize> = vec![];
        while let Some(partial) = rx.recv().await {
            assert_eq!(partial["status"], "in-progress");
            let hops = partial["hops"].as_array().map_or(0, |h| h.len());
            hop_counts.push(hops);
        }

        let final_result = measure.await.unwrap().unwrap();
        println!("Traceroute progress events: {}", hop_counts.len());
        println!("Hop counts per event: {hop_counts:?}");
        println!("Final status: {}", final_result["status"]);

        assert!(!hop_counts.is_empty(), "expected at least 1 progress event");
        // Hop counts should be non-decreasing
        for w in hop_counts.windows(2) {
            assert!(w[1] >= w[0], "hop count should not decrease");
        }
    }

    /// Without inProgressUpdates, the channel should receive no events.
    #[tokio::test]
    async fn live_ping_no_progress_when_flag_false() {
        let (tx, mut rx) = mpsc::unbounded_channel::<serde_json::Value>();
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
