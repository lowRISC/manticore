// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Host-to-device communication.
//!
//! See [`DevicePort`].

use core::cell::Cell;

use crate::io::Read;
use crate::net;

/// Represents a physical port that can be used to interact with client devices.
///
/// This for example is used for a PA RoT to send messages to a AC RoT.
///
/// This trait provides a generic mechanism for sending and receiving requests
/// from devices.
pub trait DevicePort {
    /// The send function takes a `header` and `msg` to send to a device.
    /// The implementation of this function must send the header and msg
    /// to the device specified by `dest`.
    ///
    /// This should block until the operation is complete.
    ///
    /// On success it should return nothing.
    /// On a failure an error is returned.
    fn send(
        &mut self,
        dest: u8,
        header: net::Header,
        msg: &[u8],
    ) -> Result<(), net::Error>;

    /// This is a blocking call that should wait for a response or a timeout.
    ///
    /// `duration`: Number of milliseconds to wait.
    ///
    /// If a response is received in time this should return a success.
    /// On a time out net::Error::Timeout is returned.
    /// Other errors should return a suitable net::Error as well.
    fn wait_for_response(&mut self, duration: usize) -> Result<(), net::Error>;

    /// The `process_response()` function should be called once a reply
    /// has been received for the device the `send()` operation was sent to.
    /// `msg` should contain the raw message to be processed.
    ///
    /// On success returns the response.
    fn receive_response(
        &mut self,
    ) -> Result<&mut dyn DeviceResponse, net::Error>;
}
impl dyn DevicePort {} // Ensure object-safety.

/// Provides the "response" half of a transaction with a device.
///
/// This for example is used for a PA RoT to send messages to a AC RoT.
pub trait DeviceResponse {
    /// Returns the header sent by the device for this response.
    fn header(&self) -> Result<net::Header, net::Error>;

    /// Returns the raw byte stream for the payload of the response.
    fn payload(&mut self) -> Result<&mut dyn Read, net::Error>;
}

/// A simple in-memory [`DevicePort`].
pub struct InMemDevice<'buf>(InMemInner<'buf>);

struct InMemInner<'buf> {
    rx_header: Cell<Option<net::Header>>,
    rx: &'buf [u8],
    tx_dest: Cell<u8>,
    tx_header: Cell<Option<net::Header>>,
    tx: &'buf mut [u8],
    finished: Cell<bool>,
}

impl<'buf> Default for InMemDevice<'buf> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'buf> InMemDevice<'buf> {
    /// Creates a new `InMemDevice`, with the given output buffer for holding
    /// messages to be "transmitted", acting as the final destination for
    /// replies to this host.
    pub fn new() -> Self {
        Self(InMemInner {
            rx_header: Cell::new(None),
            rx: &[],
            tx_dest: Cell::new(0),
            tx_header: Cell::new(None),
            tx: &mut [],
            finished: Cell::new(false),
        })
    }

    /// Schedules a response.
    pub fn response(&mut self, header: net::Header, message: &'buf [u8]) {
        self.0.rx_header.set(Some(header));
        self.0.rx = message;
    }
}

impl<'buf> DevicePort for InMemDevice<'buf> {
    fn send(
        &mut self,
        dest: u8,
        header: net::Header,
        msg: &[u8],
    ) -> Result<(), net::Error> {
        self.0.tx_dest.set(dest);
        self.0.tx_header.set(Some(header));
        self.0.tx.copy_from_slice(msg);

        self.0.finished.set(true);

        Ok(())
    }

    fn wait_for_response(&mut self, _timeout: usize) -> Result<(), net::Error> {
        Ok(())
    }

    fn receive_response(
        &mut self,
    ) -> Result<&mut dyn DeviceResponse, net::Error> {
        Ok(&mut self.0)
    }
}
impl DeviceResponse for InMemInner<'_> {
    fn header(&self) -> Result<net::Header, net::Error> {
        if !self.finished.get() {
            return Err(net::Error::OutOfOrder);
        }
        Ok(self.tx_header.get().unwrap())
    }

    fn payload(&mut self) -> Result<&mut dyn Read, net::Error> {
        Ok(&mut self.rx)
    }
}
