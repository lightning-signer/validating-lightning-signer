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
