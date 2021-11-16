// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Cerberus session management.
//!
//! A Cerberus cryptographic session is created via the usual ECDH scheme, using
//! [SP 800-108] as the KDF.
//!
//! # Key Derivation
//!
//! The KDF is specified by the NIST document [SP 800-108]. This document
//! defines a family of KDFs, which are parametrized over a mode and a PRF.
//! Cerberus uses the "counter" mode and HMAC with SHA-256 as its PRF.
//! This actually boils down the KDF to a single HMAC operation:
//!
//! ```text
//! session_key := HMAC(ecdh_material, 0x00000001 || L || 0x00 || C || 0x0100)
//! ```
//!
//! where each integer is encoded big-endian. The ECDH exchange itself must
//! use the P-256 curve. Implementations of [`Session`] must use this exact
//! algorithm.
//!
//! [SP 800-108]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf

use crate::crypto::hash;

#[cfg(doc)]
use crate::protocol::cerberus;

#[cfg(all(feature = "ring", feature = "std"))]
pub mod ring;

/// An error returned by an ECDH operation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Indicates that one of the state-transitioning functions was called
    /// on an incorrect state.
    ///
    /// For example, [`Session::finish_ecdh()`] can only be called after
    /// [`Session::begin_ecdh()`] is called.
    BadStateTransition,
    /// Indicates an unspecified, internal error.
    Unspecified,
}

/// A secret key returned by a [`Session`].
pub type Key = [u8; 256 / 8];

/// A manager for a Cerberus session, usable by either the host (the client)
/// or the device (the server).
///
/// A `Session` is a state machine with four states:
/// 1.  "Inactive": the starting state, indicating no session.
///         - This state may be entered via [`Session::destroy_session()`] at
///           any time.
/// 2.  "Ready": the session is configured with the challenge nonces, ready for
///     ECDH to begin.
///         - This state may be entered via [`Session::create_session()`] at
///           any time.
/// 3.  "Agreement": an ephemeral ECDH private key has been created, and is
///     pending receipt of the peer's public key to complete the ECDH
///     transaction.
///         - This state may be entered via [`Session::begin_ecdh()`], but only
///           from the "Ready" or "Active" states.
///         - [`Session::begin_ecdh()`] may be called on an active session to
///           reestablish it.
/// 4.  "Active": a session has been established, and [`Session::aes_key()`]
///     and [`Session::hmac_key()`] will produce the negotiated keys.
///         - This state may be entered via [`Session::finish_ecdh()`], but only
///           from the "Ready" state.
///
/// All transition failures must leave the `Session` as-is, except for
/// [`Session::finish_ecdh()`], which must bring it back to the "Ready" state
/// on failure. It is a programmer error to call [`Session::finish_ecdh()`]
/// out-of-order, since it's intended to be called with
/// [`Session::begin_ecdh()`] in the context of request. This transition can
/// only fail if the entire ECDH exchange fails.
///
/// Users will move through the states like so:
/// 1.  When a device receives a [`cerberus::challenge`] request that wants to
///     establish a session later, its `Session` enters the "ready" state; once
///     the response arrives, the host enters the "ready" state too.
/// 2.  The host enters the "agreement" state and sends a
///     [`cerberus::key_exchange`] request to the device with the fresh public
///     key.
/// 3.  The device also enters the "agreement" state, and then immediately
///     transitions to "active" using the host's public key. It then sends its
///     public key, along with an HMAC of its certificate using the session's
///     HMAC key, to the host.
/// 4.  After verifying the signature over the public keys, the host enters the
///     "active" state using the device's public key, and verifies the HMAC in
///     the response.
/// 5.  The device returns to the "inactive" state when receiving a
///     session-destroying [`cerberus::key_exchange`] request. Upon success,
///     the host also enters the "inactive" state.
///
/// See the [module documentation][self] for information on the key derivation
/// function used to create the HMAC and encryption keys.
pub trait Session {
    /// Begins a new session.
    ///
    /// Sessions begin when a successful [`cerberus::challenge`] command is
    /// completed. The challenge produces two nonces as a byproduct, which are
    /// used as the basis for the session.
    ///
    /// This function destroys any prior existing session.
    fn create_session(
        &mut self,
        req_nonce: &[u8],
        resp_nonce: &[u8],
    ) -> Result<(), Error>;

    /// Destroys a session without creating a new one.
    fn destroy_session(&mut self) -> Result<(), Error>;

    /// Returns the maximum number of bytes needed to encode `our_key` in
    /// [`Self::begin_ecdh()`].
    fn ephemeral_bytes(&self) -> usize;

    /// Begins an ECDH agreement.
    ///
    /// A fresh public key of length at most [`Session::ephemeral_bytes()`] is
    /// written to `our_key`. On success, returns the length of this key.
    ///
    /// `our_key` will be an ECC key using the DER encoding.
    fn begin_ecdh(&mut self, our_key: &mut [u8]) -> Result<usize, Error>;

    /// Completes the ECDH agreement, establishing an active session.
    ///
    /// `hmac_algorithm` is the client-chosen algorithm for creating HMACs
    /// throughout the session.
    ///
    /// `their_key` should contain the public key from the response to an
    /// appropriate [`cerberus::key_exchange`] request.
    ///
    /// `their_key` must be an ECC key using the DER encoding.
    fn finish_ecdh(
        &mut self,
        hmac_algorithm: hash::Algo,
        their_key: &[u8],
    ) -> Result<(), Error>;

    /// Returns the current session's AES-GCM encryption key, if a session exists.
    fn aes_key(&self) -> Option<&Key>;

    /// Returns the current session's HMAC key, if a session exists.
    fn hmac_key(&self) -> Option<(hash::Algo, &Key)>;
}
