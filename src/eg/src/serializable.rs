use std::io::Cursor;

use anyhow::{Context, Result};

pub trait SerializableCanonical {
    /// Writes an entity to a [`std::io::Write`] as canonical bytes.
    /// This uses a more compact JSON format.
    fn to_stdiowrite_canonical(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()>
    where
        Self: serde::Serialize,
    {
        serde_json::ser::to_writer(stdiowrite, self).context("Writing canonical")
    }

    /// Returns the canonical byte sequence representation of the entity.
    /// This uses a more compact JSON format.
    fn to_canonical_bytes(&self) -> Result<Vec<u8>>
    where
        Self: serde::Serialize,
    {
        let mut buf = Cursor::new(Vec::new());
        self.to_stdiowrite_canonical(&mut buf)
            .context("Writing canonical")?;
        Ok(buf.into_inner())
    }
}

pub trait SerializablePretty {
    /// Writes an entity to a [`std::io::Write`] as pretty JSON.
    fn to_stdiowrite_pretty(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()>
    where
        Self: serde::Serialize,
    {
        let mut ser = serde_json::Serializer::pretty(stdiowrite);

        self.serialize(&mut ser)
            .map_err(Into::<anyhow::Error>::into)
            .and_then(|_| ser.into_inner().write_all(b"\n").map_err(Into::into))
            .context("Writing pretty")
    }

    /// Returns a pretty JSON `String` representation of the entity.
    /// The final line will end with a newline.
    fn to_json_pretty(&self) -> String
    where
        Self: serde::Serialize,
    {
        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
    }
}
