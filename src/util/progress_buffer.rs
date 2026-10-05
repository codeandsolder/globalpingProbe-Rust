use std::collections::HashMap;

pub enum BufferMode {
    Append,
    Diff,
    Overwrite,
}

pub struct ProgressBuffer {
    buffer: HashMap<String, String>,
    offset: HashMap<String, usize>,
    mode: BufferMode,
    is_first: bool,
}

impl ProgressBuffer {
    #[must_use]
    pub fn new(mode: BufferMode) -> Self {
        Self {
            buffer: HashMap::new(),
            offset: HashMap::new(),
            mode,
            is_first: true,
        }
    }

    pub fn push(&mut self, field: &str, value: &str) {
        match self.mode {
            BufferMode::Append => {
                self.buffer
                    .entry(field.to_string())
                    .and_modify(|v| v.push_str(value))
                    .or_insert_with(|| value.to_string());
            }
            _ => {
                self.buffer.insert(field.to_string(), value.to_string());
            }
        }
    }

    pub fn take_progress(&mut self) -> HashMap<String, String> {
        if matches!(self.mode, BufferMode::Diff) {
            let mut diff = HashMap::new();
            for (field, value) in &self.buffer {
                let offset = self.offset.get(field).copied().unwrap_or(0);
                diff.insert(field.clone(), value[offset..].to_string());
                self.offset.insert(field.clone(), value.len());
            }
            diff
        } else {
            let out = self.buffer.clone();
            self.buffer.clear();
            out
        }
    }

    pub const fn is_first_progress(&mut self) -> bool {
        let f = self.is_first;
        self.is_first = false;
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_mode_concatenates_values() {
        let mut buf = ProgressBuffer::new(BufferMode::Append);
        buf.push("rawOutput", "line1\n");
        buf.push("rawOutput", "line2\n");
        let out = buf.take_progress();
        assert_eq!(out["rawOutput"], "line1\nline2\n");
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
    fn overwrite_mode_replaces_value() {
        let mut buf = ProgressBuffer::new(BufferMode::Overwrite);
        buf.push("rawOutput", "first");
        buf.push("rawOutput", "second");
        let out = buf.take_progress();
        assert_eq!(out["rawOutput"], "second");
    }

    #[test]
    fn is_first_returns_true_once() {
        let mut buf = ProgressBuffer::new(BufferMode::Append);
        assert!(buf.is_first_progress());
        assert!(!buf.is_first_progress());
    }
}
