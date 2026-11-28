use jiff::Timestamp;

pub(crate) fn wire_timestamp(timestamp: Timestamp) -> String {
    format!("{timestamp:.3}")
}

pub(crate) fn console_timestamp(timestamp: &Timestamp) -> impl std::fmt::Display + '_ {
    timestamp.strftime("%Y-%m-%d %H:%M:%S +00:00")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_utc_wire_and_console_formats() -> Result<(), jiff::Error> {
        for (input, wire, console) in [
            (
                "2024-02-29T23:59:59.999999999Z",
                "2024-02-29T23:59:59.999Z",
                "2024-02-29 23:59:59 +00:00",
            ),
            (
                "1970-01-01T00:00:00Z",
                "1970-01-01T00:00:00.000Z",
                "1970-01-01 00:00:00 +00:00",
            ),
            (
                "1969-12-31T23:59:59.000999999Z",
                "1969-12-31T23:59:59.000Z",
                "1969-12-31 23:59:59 +00:00",
            ),
        ] {
            let timestamp = input.parse()?;
            assert_eq!(wire_timestamp(timestamp), wire);
            assert_eq!(console_timestamp(&timestamp).to_string(), console);
        }
        Ok(())
    }
}
