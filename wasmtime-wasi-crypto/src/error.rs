/// This file is a complete copy of https://github.com/bytecodealliance/wasmtime/blob/a79c4b3afdf6d3678d2e2d0d4340b2fcafe7c85f/crates/wasi-http/src/p2/error.rs
use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno;
use std::error::Error;
use std::fmt;
use wasmtime::component::ResourceTableError;

/// A [`Result`] type where the error type defaults to [`CryptoError`].
pub type CryptoResult<T, E = CryptoError> = Result<T, E>;

/// A `wasi:crypto`-specific error type used to represent either a trap or an
/// [`CryptoErrno`].
///
/// Modeled after [`TrappableError`](wasmtime_wasi::TrappableError).
#[repr(transparent)]
pub struct CryptoError {
    err: wasmtime::Error,
}

impl CryptoError {
    /// Create a new `HttpError` that represents a trap.
    pub fn trap(err: impl Into<wasmtime::Error>) -> CryptoError {
        CryptoError { err: err.into() }
    }

    /// Downcast this error to an [`CryptoErrno`].
    pub fn downcast(self) -> wasmtime::Result<CryptoErrno> {
        self.err.downcast()
    }

    /// Downcast this error to a reference to an [`CryptoErrno`]
    pub fn downcast_ref(&self) -> Option<&CryptoErrno> {
        self.err.downcast_ref()
    }
}

impl From<CryptoErrno> for CryptoError {
    fn from(error: CryptoErrno) -> Self {
        Self { err: error.into() }
    }
}

impl From<ResourceTableError> for CryptoError {
    fn from(error: ResourceTableError) -> Self {
        CryptoError::trap(error)
    }
}

impl fmt::Debug for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.err.fmt(f)
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.err.fmt(f)
    }
}

impl Error for CryptoError {}
