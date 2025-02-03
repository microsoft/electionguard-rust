// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::assertions_on_constants)]
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(non_upper_case_globals)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

//use std::borrow::Cow;
//use std::collections::HashSet;
//use std::io::{BufRead, Cursor};
//use std::path::{Path, PathBuf};
//use std::str::FromStr;
//use std::sync::OnceLock;

//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
//use proc_macro2::{Ident,Literal,TokenStream};
//use quote::{format_ident, quote, ToTokens, TokenStreamExt};
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
use static_assertions::assert_obj_safe;
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};

//=================================================================================================|

pub trait ResourcePersistence {
    //? TODO
}

assert_obj_safe!(ResourcePersistence);

//-------------------------------------------------------------------------------------------------|
//? /// Identifies a storage operation in error reporting. See [`ElectionDataObjectStorageError`] for details.
//? #[derive(Debug, derive_more::Display)]
//? pub enum EdoPersistentStorageOpForError {
//?     CheckExistence,
//?     ReadExisting,
//?     WriteNew,
//? }
//-------------------------------------------------------------------------------------------------|
//? /// The [`Error`](std::error::Error) type returned by [`ElectionDataObjectStorage`] functions.
//? #[allow(non_camel_case_types)]
//? #[derive(thiserror::Error, Clone, Debug)]
//? pub enum EdoPersistentStorageError {
//?     #[error("The object `{0}` does not currently exist in persisted storage.")]
//?     ReadExisting_DoesNotCurrentlyExist(ElectionDataObjectId),
//?
//?     #[error("While attempting to write `{0}` to persistent storage, it turned out the object already exists.")]
//?     WriteNew_AlreadyExists(ElectionDataObjectId),
//?
//?     #[error("While attempting to `{1}` on `{0}` persistent storage, encountered IO error: {2}")]
//?     StdIoError(
//?         ElectionDataObjectId,
//?         EdoPersistentStorageOpForError,
//?         std::io::Error,
//?     ),
//?
//?     #[error("Todo")]
//?     Todo,
//? }
//-------------------------------------------------------------------------------------------------|
//? /// Provides access to persistent storage of election data objects.
//? pub trait EdoPersistentStorage {
//?     /// Check if we might be able to get a stream to a persisted election data object.
//?     ///
//?     /// If you're planning to read it, consider just calling [`read_existing`] and handle any
//?     /// [`DoesNotCurrentlyExist`](ElectionDataObjectPersistentStorageReadError::DoesNotCurrentlyExist) error.
//?     fn check_exists(
//?         &self,
//?         eg_obj_id: ElectionDataObjectId,
//?     ) -> Result<bool, EdoPersistentStorageError>;
//?
//?     /// Get a stream to read an existing persisted election data object.
//?     ///
//?     /// Fails if the object does not exist.
//?     fn read_existing(
//?         &self,
//?         eg_obj_id: ElectionDataObjectId,
//?     ) -> Result<Box<dyn std::io::Read>, EdoPersistentStorageError>;
//?
//?     /// Get a stream to write a new persisted election data object.
//?     ///
//?     /// Fails if the object already exists.
//?     fn write_new(
//?         &self,
//?         eg_obj_id: ElectionDataObjectId,
//?     ) -> Result<Box<dyn std::io::Write>, EdoPersistentStorageError>;
//? }
//-------------------------------------------------------------------------------------------------|
//? assert_obj_safe!(EdoPersistentStorage);
//-------------------------------------------------------------------------------------------------|
//? pub struct PersistentStorage {
//?     //? archive directory
//? }
//? impl PersistentStorage {
//?     #[allow(clippy::new_without_default)]
//?     pub fn new() -> Self {
//?         PersistentStorage {}
//?     }
//? }
//? impl EdoPersistentStorage for PersistentStorage {
//?     fn check_exists(
//?         &self,
//?         eg_obj_id: ElectionDataObjectId,
//?     ) -> Result<bool, EdoPersistentStorageError> {
//?         Err(EdoPersistentStorageError::Todo)
//?     }
//?
//?     fn read_existing(
//?         &self,
//?         eg_obj_id: ElectionDataObjectId,
//?     ) -> Result<Box<dyn std::io::Read>, EdoPersistentStorageError> {
//?         Err(EdoPersistentStorageError::Todo)
//?     }
//?
//?     fn write_new(
//?         &self,
//?         eg_obj_id: ElectionDataObjectId,
//?     ) -> Result<Box<dyn std::io::Write>, EdoPersistentStorageError> {
//?         Err(EdoPersistentStorageError::Todo)
//?     }
//? }
//? impl EdoSource for PersistentStorage {
//?     fn source_name(&self) -> Result<String, EdoSourceError> {
//?         Ok("Filesystem".to_string())
//?     }
//?
//?     fn source_kind(&self) -> EdoSourceKind {
//?         EdoSourceKind::PersistentStorage
//?     }
//?
//?     fn preferred_priority_pr(&self) -> (u8, u8) {
//?         (0x80, 0x80)
//?     }
//?
//?     fn try_produce(
//?         &self,
//?         eg_obj_id: ElectionDataObjectId,
//?         edo_map: &EdoMap,
//?         //? Metadata
//?     ) -> Result<bool, EdoSourceError> {
//?         Err(EdoSourceError::Todo)
//?     }
//? }
