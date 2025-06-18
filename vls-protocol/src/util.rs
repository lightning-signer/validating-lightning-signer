#![cfg(feature = "developer")]
use serde_bolt::{io::Result, io::Write};

// Used to record written length

pub(crate) struct MeasuredWriter<'a, W>
where
    W: Write + ?Sized,
{
    writer: &'a mut W,
    len: usize,
}

impl<'a, W> MeasuredWriter<'a, W>
where
    W: Write + ?Sized,
{
    // Wrap an existing writer
    pub(crate) fn wrap(writer: &'a mut W) -> Self {
        Self { writer, len: 0 }
    }

    // Report number of bytes written
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

impl<'a, W> Write for MeasuredWriter<'a, W>
where
    W: Write + ?Sized,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let len = self.writer.write(buf)?;
        self.len += len;
        Ok(len)
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
#[cfg(feature = "developer")]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use serde_bolt::io::{Result, Write};

    struct TestWriter {
        buffer: Vec<u8>,
        error_on_write: bool,
        partial_write: Option<usize>,
    }

    impl TestWriter {
        fn new() -> Self {
            Self { buffer: Vec::new(), error_on_write: false, partial_write: None }
        }

        fn with_error() -> Self {
            Self { buffer: Vec::new(), error_on_write: true, partial_write: None }
        }

        fn with_partial_write(len: usize) -> Self {
            Self { buffer: Vec::new(), error_on_write: false, partial_write: Some(len) }
        }
    }

    impl Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            if self.error_on_write {
                return Err(serde_bolt::io::Error::new(
                    serde_bolt::io::ErrorKind::Other,
                    "write error",
                ));
            }
            let len = self.partial_write.unwrap_or(buf.len());
            let write_len = len.min(buf.len());
            self.buffer.extend_from_slice(&buf[..write_len]);
            Ok(write_len)
        }

        fn flush(&mut self) -> Result<()> {
            if self.error_on_write {
                return Err(serde_bolt::io::Error::new(
                    serde_bolt::io::ErrorKind::Other,
                    "flush error",
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn test_measured_writer_write() {
        let mut buffer = Vec::new();
        let mut measured = MeasuredWriter::wrap(&mut buffer);
        let data = b"hello";

        let written = measured.write(data).expect("Write should succeed");
        assert_eq!(written, 5);
        assert_eq!(measured.len(), 5);
        assert_eq!(buffer, b"hello");
    }

    #[test]
    fn test_measured_writer_multiple_writes() {
        let mut buffer = Vec::new();
        let mut measured = MeasuredWriter::wrap(&mut buffer);
        let data1 = b"hello";
        let data2 = b"world";

        let written1 = measured.write(data1).expect("First write should succeed");
        let written2 = measured.write(data2).expect("Second write should succeed");
        assert_eq!(written1, 5);
        assert_eq!(written2, 5);
        assert_eq!(measured.len(), 10);
        assert_eq!(buffer, b"helloworld");
    }

    #[test]
    fn test_measured_writer_partial_write() {
        let mut mock_writer = TestWriter::with_partial_write(3);
        let mut measured = MeasuredWriter::wrap(&mut mock_writer);
        let data = b"hello";

        let written = measured.write(data).expect("Partial write should succeed");
        assert_eq!(written, 3);
        assert_eq!(measured.len(), 3);
        assert_eq!(mock_writer.buffer, b"hel");
    }

    #[test]
    fn test_measured_writer_write_error() {
        let mut mock_writer = TestWriter::with_error();
        let mut measured = MeasuredWriter::wrap(&mut mock_writer);
        let data = b"hello";

        let result = measured.write(data);
        assert!(result.is_err());
        assert_eq!(measured.len(), 0);
        assert_eq!(mock_writer.buffer.len(), 0);
    }

    #[test]
    fn test_measured_writer_flush() {
        let mut buffer = Vec::new();
        let mut measured = MeasuredWriter::wrap(&mut buffer);
        let _ = measured.write(b"data");
        let _ = measured.flush();
        assert_eq!(measured.len(), 4);
        assert_eq!(buffer, b"data");
    }
}
