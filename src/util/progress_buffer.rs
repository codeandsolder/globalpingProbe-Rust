use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferMode {
    Append,
    Diff,
    Overwrite,
}

pub struct ProgressBuffer {
    buffer: HashMap<String, String>,
    offset: HashMap<String, usize>,
    mode: BufferMode,
}

impl ProgressBuffer {
    #[must_use]
    pub fn new(mode: BufferMode) -> Self {
        Self {
            buffer: HashMap::new(),
            offset: HashMap::new(),
            mode,
        }
    }

    #[must_use]
    pub const fn overwrite(&self) -> bool {
        matches!(self.mode, BufferMode::Overwrite)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn push(&mut self, field: &str, value: &str) {
        match self.mode {
            BufferMode::Append => {
                self.buffer
                    .entry(field.to_string())
                    .and_modify(|current| current.push_str(value))
                    .or_insert_with(|| value.to_string());
            }
            BufferMode::Diff | BufferMode::Overwrite => {
                self.buffer.insert(field.to_string(), value.to_string());
            }
        }
    }

    pub fn take_progress(&mut self) -> HashMap<String, String> {
        let current = std::mem::take(&mut self.buffer);
        if !matches!(self.mode, BufferMode::Diff) {
            return current;
        }

        current
            .into_iter()
            .map(|(field, value)| {
                let offset = self.offset.get(&field).copied().unwrap_or(0);
                let safe_offset = value.floor_char_boundary(offset.min(value.len()));
                let delta = value[safe_offset..].to_string();
                self.offset.insert(field.clone(), value.len());
                (field, delta)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_mode_concatenates_values_and_clears_after_take() {
        let mut buf = ProgressBuffer::new(BufferMode::Append);
        buf.push("rawOutput", "line1\n");
        buf.push("rawOutput", "line2\n");
        let out = buf.take_progress();
        assert_eq!(out["rawOutput"], "line1\nline2\n");
        assert!(buf.is_empty());
    }

    #[test]
    fn diff_mode_returns_only_new_content() {
        let mut buf = ProgressBuffer::new(BufferMode::Diff);
        buf.push("rawOutput", "line1\n");
        let first = buf.take_progress();
        assert_eq!(first["rawOutput"], "line1\n");

        buf.push("rawOutput", "line1\nline2\n");
        let second = buf.take_progress();
        assert_eq!(second["rawOutput"], "line2\n");
    }

    #[test]
    fn diff_mode_does_not_repeat_fields_missing_from_later_updates() {
        let mut buf = ProgressBuffer::new(BufferMode::Diff);
        buf.push("rawHeaders", "content-type: text/plain");
        buf.push("rawBody", "a");
        let first = buf.take_progress();
        assert_eq!(first["rawHeaders"], "content-type: text/plain");
        assert_eq!(first["rawBody"], "a");

        buf.push("rawBody", "ab");
        let second = buf.take_progress();
        assert_eq!(second["rawBody"], "b");
        assert!(!second.contains_key("rawHeaders"));
    }

    #[test]
    fn overwrite_mode_replaces_values_and_clears_after_take() {
        let mut buf = ProgressBuffer::new(BufferMode::Overwrite);
        buf.push("rawOutput", "first");
        buf.push("rawOutput", "second");
        let out = buf.take_progress();
        assert_eq!(out["rawOutput"], "second");
        assert!(buf.is_empty());
    }
}
