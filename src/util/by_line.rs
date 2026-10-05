// Splits a stream of bytes into complete lines, mirroring src/lib/by-line.ts
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

/// Read `reader` line by line and invoke `on_line` for each complete line.
///
/// # Errors
/// Returns an error if the underlying asynchronous reader fails.
pub async fn by_line<R, F>(reader: R, mut on_line: F) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    F: FnMut(String),
{
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        on_line(line);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn splits_multiline_input() {
        let input = Cursor::new("line1\nline2\nline3\n");
        let mut collected = Vec::new();
        by_line(input, |l| collected.push(l)).await.unwrap();
        assert_eq!(collected, vec!["line1", "line2", "line3"]);
    }

    #[tokio::test]
    async fn handles_empty_input() {
        let input = Cursor::new("");
        let mut collected = Vec::new();
        by_line(input, |l| collected.push(l)).await.unwrap();
        assert!(collected.is_empty());
    }
}
