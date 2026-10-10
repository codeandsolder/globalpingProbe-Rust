# globalping-probe (Rust)

A Rust rewrite of the [globalping-probe](https://github.com/jsdelivr/globalping-probe) — a lightweight network measurement agent that connects to the Globalping API via socket.io, receives jobs (ping, traceroute, DNS, MTR, HTTP), executes them on Linux, and streams results back in real time.

**Why Rust?**
- Memory safety at compile time — no buffer overflows, use-after-free, or data races
- ~70 % RAM reduction vs Node.js (target: 10–20 MB idle vs 50–70 MB)
- Single static probe binary — no Node.js runtime or `node_modules`; optional signed WASM behavior updates stay behind the native trust boundary
- Async via Tokio — maps directly onto the probe's concurrent measurement model

---

## Requirements

| Tool | Version | Notes |
|---|---|---|
| Rust (stable) | 1.99.0 | edition 2024 |
| Linux (WSL Ubuntu-24.04 or native) | — | Build and run target |
| `libssl-dev`, `pkg-config` | — | Required by `rust_socketio` → `openssl-sys` |
| `traceroute` | any | Must have `cap_net_raw` for ICMP mode (see below) |
| `ping`, `dig`, `mtr`, `curl` | system | Used by measurement commands |

### First-time setup (WSL / Ubuntu)

```bash
sudo apt-get install -y libssl-dev pkg-config traceroute mtr-tiny dnsutils curl
# Grant ICMP capability so traceroute works without root:
sudo setcap cap_net_raw+ep $(readlink -f $(which traceroute))
```

---

## Project Structure

```
globalPing-Rust/
├── src/
│   ├── main.rs               Binary entry point — reads env vars, starts probe
│   ├── lib.rs                Library root — re-exports all modules for tests
│   ├── config.rs             AppConfig skeleton (future config-file support)
│   ├── command/
│   │   ├── mod.rs            MeasurementCommand trait + ProgressTx type alias
│   │   ├── ping/             PingCommand — spawns system ping, line-by-line output
│   │   │   ├── mod.rs        run_icmp(), run_with_progress(), build_args()
│   │   │   └── parse.rs      ParsedPing, PingStatus, timing + stats extraction
│   │   ├── traceroute/       TracerouteCommand — spawns traceroute, per-hop streaming
│   │   │   ├── mod.rs        run_traceroute(), HOP_LINE regex, build_args()
│   │   │   └── parse.rs      ParsedTraceroute, hop/timing extraction
│   │   ├── dns/              DnsCommand — spawns dig, classic + trace modes
│   │   │   ├── mod.rs        query_classic(), query_trace(), build_args()
│   │   │   └── parse.rs      ParsedDns, answer/metadata extraction
│   │   ├── mtr.rs            MtrCommand — spawns mtr --json, parses hub list
│   │   └── http.rs           HttpCommand — spawns curl, parses headers/body/TLS
│   ├── probe/
│   │   ├── mod.rs            Module registry
│   │   ├── client.rs         Socket.io client, connect/reconnect loop, dispatch
│   │   ├── dns_servers.rs    get_dns_servers() — reads /etc/resolv.conf
│   │   ├── limiter.rs        MeasurementLimiter — semaphore cap of 3, wait_idle()
│   │   ├── progress.rs       ProgressEmitter — drains channel → socket.io events
│   │   ├── reconnect.rs      ConnectOutcome, classify_error(), ExponentialBackoff
│   │   ├── stats.rs          MeasurementStats — lock-free atomic counters, take()
│   │   ├── sysinfo.rs        total_memory_bytes(), disk_info_mb()
│   │   └── uuid.rs           ProbeUuid::load_or_create(), resolve_uuid_path()
│   ├── status/
│   │   ├── mod.rs
│   │   ├── status_manager.rs StatusManager — aggregates ping/ICMP/proxy/disconnect state
│   │   ├── disconnect.rs     DisconnectTracker — TTL window, triggers at max
│   │   ├── ping_test.rs      PingTest — IPv4/IPv6 reachability QA
│   │   └── icmp_tcp_test.rs  IcmpTcpTest — latency diff VPN detection
│   └── util/
│       ├── mod.rs
│       ├── by_line.rs        by_line() — async line-by-line subprocess reader
│       ├── logger.rs         init() — tracing-subscriber with env-filter
│       ├── output_limit.rs   truncate_output(), limit_raw_output() — 10 KiB cap
│       ├── private_ip.rs     is_ip_private() — blocks all RFC-reserved ranges
│       ├── progress_buffer.rs ProgressBuffer — Append / Diff / Overwrite modes
│       └── tcp_ping.rs       TCP ping via connect() for latency measurement
├── tests/
│   └── integration/
│       ├── mod.rs
│       ├── dns_test.rs             DNS command: args, parse, live queries
│       ├── graceful_shutdown_test.rs  wait_idle() drain behaviour
│       ├── http_test.rs            HTTP command: args, parse, TLS, live fetch
│       ├── mtr_test.rs             MTR command: args, parse, live trace
│       ├── output_limit_test.rs    rawOutput truncation, UTF-8 boundary safety
│       ├── ping_test.rs            Ping command: args, parse, live ping
│       ├── private_ip_test.rs      Full RFC-reserved range + public IP coverage
│       ├── probe_test.rs           UUID, sysinfo, DNS servers, reconnect, limiter
│       ├── progress_buffer_test.rs ProgressBuffer cross-call accumulation
│       ├── progress_updates_test.rs In-progress streaming, channel mechanics
│       ├── stats_reporting_test.rs MeasurementStats counters, timeout constant
│       ├── status_test.rs          StatusManager state machine, live ICMP/TCP
│       └── traceroute_test.rs      Traceroute command: args, parse, live trace
├── Cargo.toml                Dependencies, build profiles
└── .gitignore
```

---

## Build

```bash
# Inside WSL / Linux:
source ~/.cargo/env
cargo build --all          # debug build
cargo build --release      # optimised, stripped, production binary
```

Output:
- Debug: `target/debug/globalping-probe`
- Release: `target/release/globalping-probe`

---

## Run

```bash
GP_ADOPTION_TOKEN=<token> \
GP_API_HOST=https://api.globalping.io \
RUST_LOG=info \
./target/debug/globalping-probe
```

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `GP_ADOPTION_TOKEN` | _(none)_ | Adoption token sent in WebSocket handshake |
| `GP_API_HOST` | `https://api.globalping.io` | Globalping API endpoint |
| `GP_PING_TARGET` | `api.globalping.io` | Target for periodic QA ping tests |
| `GP_BEHAVIOR_VERIFYING_KEY` | _(none)_ | 64-hex-character Ed25519 public key that explicitly enables trusted WASM behavior bootstrap |
| `GP_BEHAVIOR_ROOT` | `/.globalping-behavior` | Absolute persistent active/previous behavior-slot directory; only used when behavior bootstrap is enabled |
| `GP_BEHAVIOR_UPDATE_URL` | _(none)_ | Optional HTTPS directory serving signed `manifest.json` and `component.wasm`; redirects, embedded credentials, query strings, and fragments are rejected |
| `GP_BEHAVIOR_UPDATE_INTERVAL_SECS` | `300` | Signed behavior update polling interval; valid only when `GP_BEHAVIOR_UPDATE_URL` is set |
| `RUST_LOG` | `info` | Log level (`error`, `warn`, `info`, `debug`, `trace`) |
| `RUST_BACKTRACE` | `0` | Set to `1` for panic backtraces |

The probe UUID is persisted to `/.globalping-probe-uuid` (falls back to `$HOME/.globalping-probe-uuid` if the root path is not writable).

Behavior bootstrap is opt-in and fail-closed. With no `GP_BEHAVIOR_*` variables, startup remains native-only. If any behavior option is set, `GP_BEHAVIOR_VERIFYING_KEY` is mandatory; persisted behavior is re-verified and self-tested before use. The update URL is only a transport/discovery source—the locally provisioned Ed25519 key, manifest signature, SHA-256 digest, ABI/supervisor compatibility, and monotonic sequence decide whether an artifact can activate. Put `GP_BEHAVIOR_ROOT` on persistent storage if active/rollback slots must survive container or host replacement. When behavior is active, native execution is shared with the bounded WASM host rather than duplicated. A successful structurally valid verified WASM final result is authoritative even if the diagnostic native oracle diverges; divergence is counted and logged for rollout diagnostics but does not advance automatic rollback. Only attributable component faults (for example traps/call failures, rejected authorized jobs, policy violations, or malformed typed final output) advance the rollback streak. Component/native execution faults use the already-computed native result without rerunning the measurement. When behavior is active, bounded WASM progress is API-facing too; native progress is suppressed on the shared execution and remains only for native-only startup or pre-start behavior fallback. Behavior ABI v6 carries an explicit append/diff/overwrite progress mode, so the verified component—not native command dispatch—owns progress coalescing policy on the behavior path.

### Packaging signed behavior updates

The signing key stays outside the probe runtime. Build the WASIp2 behavior component, then use the separate offline packer to create the exact two files consumed by `GP_BEHAVIOR_UPDATE_URL`:

```bash
cargo +1.99.0 build --locked --release \
  -p globalping-behavior --target wasm32-wasip2

printf '%s\n' "$GP_BEHAVIOR_SIGNING_SEED_HEX" | \
  cargo +1.99.0 run --locked --no-default-features --features behavior-artifact --bin globalping-behavior-pack -- \
    --component target/wasm32-wasip2/release/globalping_behavior.wasm \
    --output-dir target/behavior-release-42 \
    --sequence 42 \
    --build-id git-$(git rev-parse --short=12 HEAD) \
    --signing-key -
```

`--signing-key` accepts either `-` for stdin or a file containing exactly a 32-byte Ed25519 seed encoded as 64 hexadecimal characters. The sequence must be positive and strictly newer than the probe's persisted accepted high-water mark. The output directory must not already exist; on success it contains only `manifest.json` and `component.wasm`. The packer hashes and signs the component, then round-trips the pair through the production verifier before writing it. Publish the pair together under the configured HTTPS update directory; never place private signing material on the probe host.

---

## Test

```bash
cargo test --all                          # all tests (unit + integration)
cargo test --lib                          # unit tests only
cargo test --test integration             # integration tests only
cargo test --all -- --nocapture           # show stdout during tests
cargo test <name>                         # run tests matching name
```

The Rust 1.99 CI matrix covers unit, integration, signed-behavior runtime, deterministic differential, and strict Clippy/rustdoc gates.

### Test layout

| Suite | Location | What it tests |
|---|---|---|
| Unit | `src/**/*.rs` `#[cfg(test)]` blocks | Pure logic, no I/O, no child processes |
| Integration | `tests/integration/*.rs` | Multiple modules together; live network where `#[cfg(target_os = "linux")]` |

Live tests (ping, traceroute, DNS, HTTP) require outbound internet access and the system tools installed.

---

## Architecture

```
main.rs
  └─ probe::client::run(ClientConfig)
       ├─ connect_once()  ─────────────────────────────────────────────────────┐
       │    ├─ ClientBuilder (rust_socketio)                                   │
       │    │    ├─ on("connect")         → emit status + DNS                  │
       │    │    ├─ on("disconnect")      → signal Transient outcome           │
       │    │    ├─ on("error")           → classify_error() → signal outcome  │
       │    │    ├─ on("probe:sigkill")   → std::process::exit(0)              │
       │    │    ├─ on("api:connect:*")   → location / IP / proxy events       │
       │    │    └─ on("probe:measurement:request") → dispatch()               │
       │    ├─ run_status_loop()          10-min ping + ICMP/TCP + DNS refresh  │
       │    ├─ run_stats_loop()           60-sec stats flush → probe:stats:report
       │    └─ select! { shutdown | outcome signal }                           │
       │         └─ on CleanShutdown: set_sigterm → drain limiter → disconnect │
       └─ reconnect_delay() + ExponentialBackoff                               │

dispatch(req, client, status, limiter, stats)
  ├─ limiter.try_acquire()         reject if at cap (3)
  ├─ status check                  reject if not "ready"
  ├─ client.emit("probe:measurement:ack")
  ├─ make_command(type)            ping | dns | traceroute | mtr | http
  ├─ stats.record_start()
  ├─ tokio::time::timeout(30s)
  │    ├─ if inProgressUpdates:
  │    │    ├─ unbounded_channel()
  │    │    ├─ ProgressEmitter::forward(rx)  ← spawned task
  │    │    └─ cmd.run_with_progress(opts, tx)
  │    └─ else: cmd.run(opts)
  ├─ stats.record_finish()
  ├─ limit_raw_output()            cap rawOutput at 10 KiB
  └─ client.emit("probe:measurement:result")
```

### Key design decisions

| Decision | Rationale |
|---|---|
| `ProgressTx = UnboundedSender<Value>` in `command/mod.rs` | Keeps commands unaware of socket.io; avoids circular dependency |
| `OutcomeSignal` (`Arc<Mutex<Option>>` + `Notify`) | Bridges `'static` event-handler closures back to async `connect_once` |
| `limiter.wait_idle()` acquires all semaphore permits | Elegant drain: blocks until every slot is returned, no polling |
| Lock-free `AtomicU64` for stats | No contention between concurrent measurement tasks |
| `limit_raw_output` at dispatch level | One enforcement point covers all command types |

---

## Reconnect behaviour

| Outcome | Delay | Notes |
|---|---|---|
| `Transient` | Exponential 1 s → 300 s | Network blips, socket errors |
| `IpLimitOrVpn` | Fixed 60 s | API rejected due to IP policy |
| `MetadataError` | Fixed 5 s | Bad probe metadata, retry after fix |
| `InvalidVersion` | _(exit 1)_ | Server rejected our version — fatal |
| `CleanShutdown` | _(stop loop)_ | SIGTERM / CTRL-C |

---

## Implementation status

| Feature | Status |
|---|---|
| Socket.io probe client (connect / reconnect / event loop) | Done |
| Measurement dispatch (ping, traceroute, DNS, MTR, HTTP) | Done |
| In-progress streaming (`probe:measurement:progress`) | Done |
| Measurement timeout (30 s hard cap) | Done |
| Concurrency limiter (max 3 simultaneous measurements) | Done |
| Graceful shutdown (drain in-flight before disconnect) | Done |
| Stats reporting (`probe:stats:report` every 60 s) | Done |
| DNS periodic refresh (every 10 min via status loop) | Done |
| rawOutput size limiting (10 KiB cap, UTF-8 safe) | Done |
| Probe UUID persistence (`load_or_create`, fallback path) | Done |
| Status manager (ping / ICMP-TCP / proxy / disconnect) | Done |
| Exponential backoff reconnect | Done |
| Private IP filtering (all RFC-reserved ranges) | Done |
| Adoption token in handshake URL | Done |

---

## Security

The probe executes network measurements requested by the API by shelling out to
system tools (`ping`, `traceroute`, `mtr`, `dig`, `curl`, `openssl`). Every job
field (`target`, `resolver`, `Host`, `path`, `query`, headers) is therefore
**untrusted input**, and the probe is designed to stay safe even against a
hostile or compromised API. A self-audit of that attack surface was performed;
the findings below were fixed and covered with regression tests.

### Audit findings (all fixed)

| Severity | Issue | Fix |
|---|---|---|
| **Critical** | **Command injection (RCE)** — TLS certificate enrichment built an `sh -c` string with the HTTPS `Host` value interpolated in. `Host` is never used for DNS resolution and was unvalidated, so a job with `Host: x; <command>` executed arbitrary shell. | `enrich_tls` now spawns `openssl` with an explicit argv and pipes data over stdin — **no shell, no temp files, no string interpolation**. |
| **High** | **Argument injection** — `target`/`resolver` were passed to the tools as bare arguments; a value like `-f…` was accepted (validation only ran the private-IP check *if the value already parsed as an IP*) and would be read by the tool as a flag. | New strict allow-list (`util::validate::is_safe_host`) rejects leading `-`, whitespace, and shell metacharacters; applied to every command's `target`, `resolver`, and `Host`. |
| **High** | **SSRF filter bypass** — IPv4-mapped IPv6 (`::ffff:127.0.0.1`) and NAT64 (`64:ff9b::/96`) were not normalised, so they slipped past the private-range filter and could reach `localhost` / `169.254.169.254` (cloud metadata). | `is_ip_private` now canonicalises mapped / NAT64 addresses to their embedded IPv4 before the range check. |
| **Medium** | **DNS SSRF** — the DNS command had no private-IP check at all; a custom `resolver` + `port` could be aimed at internal hosts, turning the probe into a port scanner. | DNS now validates the resolver and rejects private/internal resolver IPs. |
| **Low** | **Memory DoS** — the HTTP body file was read fully into memory before truncation. | Bounded read caps memory regardless of response size. |

### Defense-in-depth already in place

- **No shell anywhere** — every external tool is spawned with an explicit argv
  (`Command::new(...).args(...)`), so there is no shell to interpret metacharacters.
- **Private/SSRF filtering** runs both *before* spawning (on the requested target)
  and *after* name resolution (on the address actually used), in every command.
- **Hard limits**: 30 s per-measurement timeout, max 3 concurrent measurements,
  10 KiB `rawOutput` / body / header caps (UTF-8-boundary-safe).
- **Least privilege**: container runs the binary with only `cap_net_raw` on `ping`;
  no extra capabilities, no root entrypoint logic.

### Dependency audit

`cargo audit` reports **no known vulnerabilities** in the dependency tree. Three
transitive crates (`backoff`, `instant`, `rustls-pemfile`) carry informational
*unmaintained* advisories only.

### Running the security tests

```bash
cargo test --lib                                   # all unit tests incl. security
cargo test --lib validate::                        # input allow-list
cargo test --lib private_ip::                      # SSRF / mapped-IPv6 filtering
cargo test --lib validate_tests::                  # HTTP injection regressions
cargo audit                                        # dependency CVE scan
```

---

## Dependencies

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime (full feature set) |
| `anyhow` | Ergonomic error propagation |
| `thiserror` | Typed error definitions |
| `async-trait` | Async methods in traits |
| `tracing` / `tracing-subscriber` | Structured logging with env-filter |
| `serde` / `serde_json` | Serialization for API messages |
| `rust_socketio` | socket.io v4 client (async feature) |
| `uuid` | Probe UUID generation |
| `once_cell` | Lazy statics (regex, private-IP table) |
| `regex` | Packet-line / hop-line matching for in-progress streaming |
| `ipnet` | CIDR range parsing for private IP detection |
| `futures-util` | `.boxed()` for event handler closures |
| `bytes` | Binary payload type for `rust_socketio` |

**Dev only:** `tokio-test`, `mockall`, `assert_matches`, `tempfile`

---

## Performance

Measured live with probes connected to the Globalping API. Each run: 30 samples × 10 s over 5 minutes.  
Raw data in [`teststats/`](teststats/).

### Memory & CPU (idle, connected)

| Metric | Rust amd64 (WSL2) | Rust arm64 (Oracle) | Node.js amd64 (WSL2) | Node.js arm64 (Oracle) |
|---|---|---|---|---|
| RAM avg (steady state) | 19.1 MiB | **5.4 MiB** | 61.3 MiB | 50.8 MiB |
| RAM range | 15–20 MiB | 5.2–5.6 MiB | 60.5–62.2 MiB | 48.2–51.4 MiB |
| CPU avg (idle/connected) | ~0.01% | ~0.01% | ~0.05% | ~0.05% |
| CPU peak (controlled, identical ping job)¹ | — | <0.14% | — | <0.35% |

¹ From [`teststats/controlled-benchmark.md`](teststats/controlled-benchmark.md): same job (ping,
16 packets) forced at both probes in isolation from the public network, run on arm64 only.

### Image stats

| Metric | Rust | Node.js |
|---|---|---|
| Docker image size | ~58 MB | ~111 MB |
| Docker image layers | 4 | 11 |
| Startup to API connect | ~5 s | ~10 s |

**Highlights:**
- **~3.2× less RAM** than Node.js on amd64 (19 MiB vs 61 MiB)
- **~9.4× less RAM** on ARM64 (5.4 MiB vs 50.8 MiB — no V8 JIT heap)
- **~47% smaller Docker image** (58 MB vs 111 MB)
- **2× faster startup** (~5 s vs ~10 s to first API connection)
- CPU cost of a single measurement is negligible (<0.4%) for both runtimes

> amd64 figures are from WSL2 (Hyper-V VM) which adds slight memory overhead vs bare-metal Linux.
> ARM64 figures are from Oracle Cloud bare-metal and are the more accurate reference.
> See [`teststats/controlled-benchmark.md`](teststats/controlled-benchmark.md) for the full
> controlled-benchmark methodology.

---

## Reference

- Original Node.js probe: [jsdelivr/globalping-probe](https://github.com/jsdelivr/globalping-probe)
