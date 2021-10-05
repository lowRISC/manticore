// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Device-to-host communication.
//!
//! See [`HostPort`] for detailed information.

use crate::io::Cursor;
use crate::io::ReadZero;
use crate::io::Write;
use crate::net;

/// Represents a physical port that can be used to interact with host devices.
///
/// This trait provides a generic mechanism for receiving and responding to
/// requests from host devices. A value of a type implementing this trait
/// implements the entire network stack below the Cerberus protocol: it must
/// know how to speak the physical layer and assemble messages out of that
/// physical layer's packets.
///
/// `HostPort` uses the traits [`HostRequest`] and [`HostResponse`] to describe
/// a generic state machine, where a request is processed and replied to.
/// ```
/// # use manticore::net::{*, host::*};
/// fn process_request<'req>(port: &mut impl HostPort<'req>) -> Result<(), Error> {
///     let req = port.receive()?;
///     let header = req.header()?;
///     let message = req.payload()?;
///     // At this point, you can use the contents of `header`, and the
///     // bytes in `message`, to construct a response. This will involve
///     // creating a new header for the response.
///
///     // ... do stuff with `message` ...
///
/// #   let resp_header = header;
///     // After calling `reply`, `message` will be inaccessible, so it
///     // needs to be consumed as far as necessary before this step.
///     let resp = req.reply(resp_header)?;
///
///     let sink = resp.sink()?;
///     // Now, the computed response can be written to `sink`:
/// #   let resp_message = [1, 2, 3];
///     sink.write_bytes(&resp_message);
///
///     // Finally, we finish the reply by calling `finish()`. This is
///     // necessary to signal to the port that we don't plan to add any
///     // more bytes.
///     resp.finish()
/// }
/// ```
/// Note that a lot of the state transitions described above aren't perfectly
/// enforced, because, since we want `HostPort` to be object-safe, we need to
/// use references exclusively. Implementations should return
/// [`net::Error::OutOfOrder`] when this state ordering is violated.
///
/// [`InMemHost`] is a simple implementation meant for testing; its
/// documentation contains a concrete example of how to use `HostPort`'s
/// interface.
///
/// This trait is object-safe. In the future, associated types may be added,
/// but this will still permit using the trait in an object-safe way.
///
/// # Implementing this trait
///
/// A `HostPort` provides all low-level management of incoming and outgoing
/// connections. An implementation is responsible for packet assembly,
/// verifying redundancy codes, tracking AEAD tags, and so on, exposing only
/// an abstract header and a I/O for the message payload itself to Manticore.
///
/// Moreover, implementations must be "robust". If a caller, for whatever
/// reason, drops any of the returned traits on the ground and attempts to
/// begin a new connection, `HostPort` must also drop any state regarding
/// that connection on the ground. Because all of the state is tied up with
/// a mutable reference, implementors can assume that upon calling `recieve()`,
/// a client isn't holding onto stale connection state.
///
/// Implementing this trait in a way that makes the borrow checker happy is
/// non-trivial, so [`InMemHost`] is also a useful example of how to build the
/// required "Russian nesting dolls" of trait objects.
pub trait HostPort<'req> {
    /// Receives an incomming message from a connected host device.
    ///
    /// This function will block until a host device indicates that it wishes
    /// to communicate. At that point, this function will perform enough
    /// transport-level operations to populate an abstract Manticore header,
    /// and then hand off parsing to the caller.
    ///
    /// When a request begins, this function returns a [`HostRequest`], which
    /// can be used to respond to the request.
    fn receive(&mut self) -> Result<&mut dyn HostRequest<'req>, net::Error>;
}
impl dyn HostPort<'_> {} // Ensure object-safety.

/// Provides the "request" half of a transaction with a host.
///
/// See [`HostPort`](trait.HostPort.html) for more information.
pub trait HostRequest<'req> {
    /// Returns the header sent by the host for this request.
    ///
    /// This function should not be called after calling `reply()`.
    fn header(&self) -> Result<net::Header, net::Error>;

    /// Returns the raw byte stream for the payload of the request.
    ///
    /// This function should not be called after calling `reply()`.
    fn payload(&mut self) -> Result<&mut dyn ReadZero<'req>, net::Error>;

    /// Replies to this request..
    ///
    /// Calling this function performs sufficient transport-level operations to
    /// begin a response, before handing off actually composing the payload to
    /// the caller via the returned [`HostResponse`].
    fn reply(
        &mut self,
        header: net::Header,
    ) -> Result<&mut dyn HostResponse<'req>, net::Error>;
}

/// Provides the "reponse" half of a transaction with a host.
///
/// See [`HostPort`](trait.HostPort.html) for more information.
pub trait HostResponse<'req> {
    /// Returns the raw byte stream for building the payload of the response.
    ///
    /// This function should not be called after calling `finish()`.
    fn sink(&mut self) -> Result<&mut dyn Write, net::Error>;

    /// Indicates that all payload data has been written.
    ///
    /// Callers should remember to call this function; failing to do so may
    /// result in a response not being sent properly.
    fn finish(&mut self) -> Result<(), net::Error>;
}

/// A simple in-memory [`HostPort`].
///
/// This type is both useful for testing, and as a demonstration of how to use
/// a [`HostPort`] and its associated traits.
///
///
/// # Example
/// ```
/// # use manticore::io::*;
/// # use manticore::mem::*;
/// # use manticore::net;
/// # use manticore::net::*;
/// # use manticore::net::host::*;
/// # use manticore::protocol::*;
/// # use manticore::protocol::firmware_version::*;
/// # use manticore::protocol::wire::*;
/// // Build the InMemHost.
/// let mut buf = [0; 64];
/// let mut host = InMemHost::new(&mut buf);
///
/// // Prepare a request to push into the host.
/// let header = net::Header {
///     command: CommandType::FirmwareVersion,
/// };
/// let req = [0];
/// host.request(header, &req);
///
/// // Set up an arena for parsing.
/// let mut arena = [0; 64];
/// let mut arena = BumpArena::new(&mut arena);
///
/// // Prepare to recieve a message.
/// let mut host_req = host.receive()?;
/// let header = host_req.header()?;
/// assert_eq!(header.command, CommandType::FirmwareVersion);
///
/// // Parse and process the message.
/// let req = FirmwareVersionRequest::from_wire(
///     host_req.payload()?, &arena).unwrap();
/// assert_eq!(req.index, 0);
///
/// // Prepare to reply to the message.
/// let mut host_resp = host_req.reply(net::Header {
///     command: CommandType::FirmwareVersion,
/// })?;
///
/// // Build and write a reply.
/// let resp = FirmwareVersionResponse {
///     version: &[0xba; 32],
/// };
/// resp.to_wire(host_resp.sink()?).unwrap();
/// host_resp.finish()?;
///
/// // Check that we got the right data back.
/// let (header, mut resp_bytes) = host.response().unwrap();
/// assert_eq!(header.command, CommandType::FirmwareVersion);
///
/// // Now, parse the response.
/// arena.reset();
/// let resp = FirmwareVersionResponse::from_wire(&mut resp_bytes, &arena).unwrap();
/// assert_eq!(resp.version, &[0xba; 32]);
/// # Ok::<(), manticore::net::Error>(())
/// ```
pub struct InMemHost<'buf>(InMemInner<'buf>);

/// The actual guts of an `InMemHost`. This struct is used to implement the two
/// "connection state" traits used by `HostPort`.
///
/// This type is separate from `InMemHost` to hide an implementation detail. If
/// the connection state traits were implemented by `HostPort`, a caller could
/// simply convert InMemHost directly to a `HostResponse`, violating the
/// expected order of operations. This struct can be thought of as making the
/// impls of the connection traits for `InMemHost` "private".
///
/// Implementors of `HostPort` should take care that the same is not possible
/// with their implementation.
struct InMemInner<'buf> {
    rx_header: Option<net::Header>,
    rx: &'buf [u8],
    tx_header: Option<net::Header>,
    tx: Cursor<'buf>,
    finished: bool,
}

impl<'buf> InMemHost<'buf> {
    /// Creates a new `InMemHost`, with the given output buffer for holding
    /// messages to be "transmitted", acting as the final destination for
    /// replies to this host.
    pub fn new(out: &'buf mut [u8]) -> Self {
        Self(InMemInner {
            rx_header: None,
            rx: &[],
            tx_header: None,
            tx: Cursor::new(out),
            finished: false,
        })
    }

    /// Schedules a new request to be recieved, with the given request parts.
    ///
    /// Calling this function will make `recieve()` start working; otherwise,
    /// it will assert that the port is disconnected.
    pub fn request(&mut self, header: net::Header, message: &'buf [u8]) {
        self.0.rx_header = Some(header);
        self.0.rx = message;

        // Should be Cursor::seek when we get that.
        self.0.tx_header = None;
        let _ = self.0.tx.take_consumed_bytes();
        self.0.finished = false;
    }

    /// Gets the most recent response recieved until `request()` is called
    /// again.
    pub fn response(&self) -> Option<(net::Header, &[u8])> {
        self.0.tx_header.map(|h| (h, self.0.tx.consumed_bytes()))
    }
}

impl<'req, 'buf: 'req> HostPort<'req> for InMemHost<'buf> {
    fn receive(&mut self) -> Result<&mut dyn HostRequest<'req>, net::Error> {
        if self.0.rx_header.is_none() {
            return Err(net::Error::Disconnected);
        }
        Ok(&mut self.0)
    }
}

impl<'req, 'buf: 'req> HostRequest<'req> for InMemInner<'buf> {
    fn header(&self) -> Result<net::Header, net::Error> {
        self.rx_header.ok_or(net::Error::OutOfOrder)
    }

    fn payload(&mut self) -> Result<&mut dyn ReadZero<'req>, net::Error> {
        if self.rx_header.is_none() {
            return Err(net::Error::OutOfOrder);
        }
        Ok(&mut self.rx)
    }

    fn reply(
        &mut self,
        header: net::Header,
    ) -> Result<&mut dyn HostResponse<'req>, net::Error> {
        self.rx_header = None;
        self.tx_header = Some(header);
        Ok(self)
    }
}

impl<'req, 'buf: 'req> HostResponse<'req> for InMemInner<'buf> {
    fn sink(&mut self) -> Result<&mut dyn Write, net::Error> {
        if self.finished {
            return Err(net::Error::OutOfOrder);
        }
        Ok(&mut self.tx)
    }

    fn finish(&mut self) -> Result<(), net::Error> {
        self.finished = true;
        Ok(())
    }
}
