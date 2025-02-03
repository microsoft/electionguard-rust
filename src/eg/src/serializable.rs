#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)] //? TODO: Remove temp development code

use std::io::Cursor;

use anyhow::{Context, Result};
use erased_serde::{Serialize, Serializer};

use crate::eg::Eg;

static_assertions::assert_obj_safe!(erased_serde::Serialize);

/// Types which can serialize to their canonical representation.
pub trait SerializableCanonical: erased_serde::Serialize {
    /// Writes an entity to a [`std::io::Write`] as canonical bytes.
    /// This uses a more compact JSON format.
    fn to_stdiowrite_canonical(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        //let mut json = serde_json::Serializer::new(stdiowrite);
        //let json: &mut dyn erased_serde::Serializer = &mut <dyn Serializer>::erase(&mut json);
        //self.erased_serialize(json).context("Writing canonical")

        //orig serde_json::ser::to_writer(stdiowrite, self).context("Writing canonical")

        let mut ser = serde_json::ser::Serializer::new(stdiowrite);
        let erased_ser = &mut <dyn Serializer>::erase(&mut ser);
        self.erased_serialize(erased_ser)
            .context("Writing canonical")
    }

    /// Returns the canonical byte sequence representation of the entity.
    /// This uses a more compact JSON format.
    fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Cursor::new(Vec::new());
        self.to_stdiowrite_canonical(&mut buf)
            .context("Writing canonical")?;
        Ok(buf.into_inner())
    }
}

erased_serde::serialize_trait_object!(SerializableCanonical);

static_assertions::assert_obj_safe!(SerializableCanonical);

/// Types which can serialize to "pretty" (non-canonical) JSON.
pub trait SerializablePretty: erased_serde::Serialize {
    /// Writes an entity to a [`std::io::Write`] as pretty (non-canonical) JSON.
    fn to_stdiowrite_pretty(&self, stdiowrite: &mut dyn std::io::Write) -> Result<()> {
        let mut ser = serde_json::ser::Serializer::pretty(stdiowrite);
        let result = {
            let erased_ser = &mut <dyn Serializer>::erase(&mut ser);
            self.erased_serialize(erased_ser)
        };
        result
            .map_err(Into::<anyhow::Error>::into)
            .and_then(|_| ser.into_inner().write_all(b"\n").map_err(Into::into))
            .context("Writing pretty")
    }

    /// Returns a pretty JSON `String` representation of the entity.
    /// The final line will end with a newline.
    fn to_json_pretty(&self) -> String {
        /*
        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
        // */

        let mut buf = Cursor::new(Vec::new());

        // `unwrap()` is justified here because why would JSON serialization fail?
        #[allow(clippy::unwrap_used)]
        self.to_stdiowrite_pretty(&mut buf).unwrap();

        let v = buf.into_inner();

        // `unwrap()` is justified here because why would JSON serialization produce invalid UTF-8?
        #[allow(clippy::unwrap_used)]
        let mut s = String::from_utf8(v).unwrap();
        s.push('\n');
        s
    }
}

impl<T> SerializablePretty for T where T: SerializableCanonical {}
