use chrono::Utc;
use std::fmt;
use tracing::{Event, Subscriber};
use tracing_subscriber::{
    EnvFilter, Layer,
    fmt::{FmtContext, FormatEvent, FormatFields, format::Writer},
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};

use crate::util::logs_transport::ApiLogsLayer;

/// Custom log formatter that matches the Node.js probe log format exactly:
/// [YYYY-MM-DD HH:MM:SS +00:00] [LEVEL] [scope] message
struct GpFormat;

impl<S, N> FormatEvent<S, N> for GpFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        // Events bridged from the `log` crate have a hardcoded static target "log".
        // These are library-internal messages (e.g. tungstenite handshake noise) that
        // should not appear in stdout. Skip them entirely before writing anything.
        let target = event.metadata().target();
        if target == "log" {
            return Ok(());
        }

        let now = Utc::now();
        write!(writer, "[{}] ", now.format("%Y-%m-%d %H:%M:%S +00:00"))?;

        let level = match *event.metadata().level() {
            tracing::Level::ERROR => "[ERROR]",
            tracing::Level::WARN => "[WARN]",
            tracing::Level::INFO => "[INFO]",
            tracing::Level::DEBUG => "[DEBUG]",
            tracing::Level::TRACE => "[TRACE]",
        };
        write!(writer, "{level} ")?;

        // Rust module paths (containing "::") map to "general".
        // Explicit scopes like "api:connect:location" are passed through as-is.
        let scope = if target.contains("::") {
            "general"
        } else {
            target
        };
        write!(writer, "[{scope}] ")?;

        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

pub fn init() {
    // Apply filter per-layer so each layer is independently filtered.
    // A single registry-level filter would be bypassed by outer layers.
    let filter_str = "debug,hyper=warn,reqwest=warn,h2=warn,rustls=warn,log=warn";
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter_str));
    let filter2 = EnvFilter::new(filter_str);

    // GpFormat skips "log" target events directly (log-bridge events bypass per-layer
    // EnvFilter target matching due to static metadata having hardcoded target "log").
    let fmt_layer = tracing_subscriber::fmt::layer()
        .event_format(GpFormat)
        .with_filter(filter);

    // ApiLogsLayer skips "log" target events internally; the per-layer filter2
    // additionally suppresses library internals (hyper, reqwest, etc.) from the buffer.
    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(ApiLogsLayer.with_filter(filter2))
        .init();
}
