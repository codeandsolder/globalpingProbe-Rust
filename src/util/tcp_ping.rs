use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep, timeout};

#[derive(Debug, Clone)]
pub struct TcpPingProbe {
    pub rtt_ms: Option<f64>, // None = timeout or error
}

#[derive(Debug, Clone)]
pub struct TcpPingStats {
    pub min: Option<f64>,
    pub avg: Option<f64>,
    pub max: Option<f64>,
    pub mdev: Option<f64>,
    pub total: u32,
    pub rcv: u32,
    pub drop: u32,
    pub loss: f64,
}

/// Time a single TCP connect to `addr:port`.
pub async fn tcp_ping_single(addr: &str, port: u16, timeout_ms: u64) -> TcpPingProbe {
    let sock_addr: SocketAddr = match addr.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => return TcpPingProbe { rtt_ms: None },
    };
    let start = Instant::now();
    match timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(sock_addr),
    )
    .await
    {
        Ok(Ok(_)) => TcpPingProbe {
            rtt_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
        },
        _ => TcpPingProbe { rtt_ms: None },
    }
}

/// Run `packets` TCP connect probes sequentially with `interval_ms` between them.
pub async fn tcp_ping(
    addr: &str,
    port: u16,
    packets: u8,
    timeout_ms: u64,
    interval_ms: u64,
) -> TcpPingStats {
    let mut probes = Vec::with_capacity(packets as usize);
    for i in 0..packets {
        if i > 0 {
            sleep(Duration::from_millis(interval_ms)).await;
        }
        probes.push(tcp_ping_single(addr, port, timeout_ms).await);
    }
    compute_tcp_stats(&probes, packets)
}

pub fn compute_tcp_stats(probes: &[TcpPingProbe], total: u8) -> TcpPingStats {
    let rtts: Vec<f64> = probes.iter().filter_map(|p| p.rtt_ms).collect();
    let rcv = rtts.len() as u32;
    let drop = u32::from(total) - rcv;
    let loss = if total > 0 {
        (f64::from(drop) / f64::from(total)) * 100.0
    } else {
        0.0
    };

    if rtts.is_empty() {
        return TcpPingStats {
            min: None,
            avg: None,
            max: None,
            mdev: None,
            total: u32::from(total),
            rcv,
            drop,
            loss,
        };
    }

    let min = rtts.iter().copied().fold(f64::INFINITY, f64::min);
    let max = rtts.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
    let tsum2: f64 = rtts.iter().map(|r| r * r).sum();
    let mdev = avg.mul_add(-avg, tsum2 / rtts.len() as f64).max(0.0).sqrt();

    TcpPingStats {
        min: Some(min),
        avg: Some(avg),
        max: Some(max),
        mdev: Some(mdev),
        total: u32::from(total),
        rcv,
        drop,
        loss,
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_all_success() {
        let probes = vec![
            TcpPingProbe { rtt_ms: Some(10.0) },
            TcpPingProbe { rtt_ms: Some(20.0) },
            TcpPingProbe { rtt_ms: Some(30.0) },
        ];
        let s = compute_tcp_stats(&probes, 3);
        assert_eq!(s.rcv, 3);
        assert_eq!(s.drop, 0);
        assert!((s.avg.unwrap() - 20.0).abs() < 0.01);
        assert!((s.min.unwrap() - 10.0).abs() < 0.01);
        assert!((s.max.unwrap() - 30.0).abs() < 0.01);
        assert!(s.loss < 0.01);
    }

    #[test]
    fn stats_all_drop() {
        let probes = vec![TcpPingProbe { rtt_ms: None }, TcpPingProbe { rtt_ms: None }];
        let s = compute_tcp_stats(&probes, 2);
        assert_eq!(s.rcv, 0);
        assert_eq!(s.drop, 2);
        assert!((s.loss - 100.0).abs() < 0.01);
        assert!(s.avg.is_none());
    }

    #[test]
    fn stats_partial() {
        let probes = vec![
            TcpPingProbe { rtt_ms: Some(50.0) },
            TcpPingProbe { rtt_ms: None },
            TcpPingProbe {
                rtt_ms: Some(100.0),
            },
        ];
        let s = compute_tcp_stats(&probes, 3);
        assert_eq!(s.rcv, 2);
        assert_eq!(s.drop, 1);
        assert!((s.loss - 33.333).abs() < 0.1);
        assert!((s.avg.unwrap() - 75.0).abs() < 0.01);
    }

    #[test]
    fn stats_mdev_zero_when_identical_rtts() {
        let probes = vec![TcpPingProbe { rtt_ms: Some(10.0) }; 3];
        let s = compute_tcp_stats(&probes, 3);
        assert!(
            s.mdev.unwrap() < 0.001,
            "mdev should be ~0 for identical RTTs"
        );
    }
}
