// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A TCP-based Manticore `HostPort`.
//!
//! This module defines an ad-hoc binding of Cerberus over TCP (termed
//! "Cerberus over TCP"). This binding of Manticore implements the abstract
//! Cerberus header as three bytes, described as a packed C struct:
//! ```text
//! struct TcpCerberus {
//!   command_type: u8,
//!   payload_len: u16,
//! }
//! ```
//!
//! This module also provides a binding of SPDM, which uses a four-byte header:
//! ```text
//! struct TcpSpdm {
//!   total_len: u16,
//!   version: u8,
//!   command: u8,
//! }
//! ```
//! Here, `total_len` includes the four bytes of the header, and the two bytes
//! that follow are the leading version and command bytes of a generic SPDM
//! message.

use std::any::type_name;
use std::io::Read as _;
use std::io::Write as _;
use std::net::TcpListener;
use std::net::TcpStream;

use manticore::io;
use manticore::mem::Arena;
use manticore::net;
use manticore::net::host::HostPort;
use manticore::net::host::HostRequest;
use manticore::net::host::HostResponse;
use manticore::protocol;
use manticore::protocol::cerberus;
use manticore::protocol::spdm;
use manticore::protocol::wire::FromWire;
use manticore::protocol::wire::ToWire;
use manticore::protocol::wire::WireEnum;
use manticore::protocol::Command;
use manticore::protocol::Message;
use manticore::server;
use manticore::Result;
use manticore::{check, fail};

/// Sends `req` to a virtual RoT listening on `localhost:{port}`, using
/// Cerberus-over-TCP.
///
/// Blocks until a response comes back.
pub fn send_cerberus<
    'a,
    Cmd: Command<'a, CommandType = cerberus::CommandType>,
>(
    port: u16,
    req: Cmd::Req,
    arena: &'a dyn Arena,
) -> Result<
    Result<Cmd::Resp, protocol::Error<'a, Cmd>>,
    server::Error<net::CerberusHeader>,
> {
    log::info!("connecting to 127.0.0.1:{}", port);
    let mut conn = TcpStream::connect(("127.0.0.1", port)).map_err(|e| {
        log::error!("{}", e);
        net::Error::Io(io::Error::Internal)
    })?;
    let mut writer = Writer::new(net::CerberusHeader {
        command: <Cmd::Req as Message>::TYPE,
    });
    log::info!("serializing {}", type_name::<Cmd::Req>());
    req.to_wire(&mut writer)?;
    writer.finish(&mut conn)?;

    log::info!("waiting for response");
    let (header, len) = net::CerberusHeader::from_tcp(&mut conn)?;
    let mut r = TcpReader { tcp: conn, len };

    if header.command == <Cmd::Resp as Message>::TYPE {
        log::info!("deserializing {}", type_name::<Cmd::Resp>());
        Ok(Ok(FromWire::from_wire(&mut r, arena)?))
    } else if header.command == cerberus::CommandType::Error {
        log::info!("deserializing {}", type_name::<protocol::Error<'a, Cmd>>());
        Ok(Err(fail!(FromWire::from_wire(&mut r, arena)?)))
    } else {
        Err(net::Error::BadHeader.into())
    }
}

/// Sends `req` to a virtual RoT listening on `localhost:{port}`, using
/// Spdm-over-TCP.
///
/// Blocks until a response comes back.
pub fn send_spdm<'a, Cmd: Command<'a, CommandType = spdm::CommandType>>(
    port: u16,
    req: Cmd::Req,
    arena: &'a dyn Arena,
) -> Result<
    Result<Cmd::Resp, protocol::Error<'a, Cmd>>,
    server::Error<net::SpdmHeader>,
> {
    log::info!("connecting to 127.0.0.1:{}", port);
    let mut conn = TcpStream::connect(("127.0.0.1", port)).map_err(|e| {
        log::error!("{}", e);
        net::Error::Io(io::Error::Internal)
    })?;
    let mut writer = Writer::new(net::SpdmHeader {
        command: <Cmd::Req as Message>::TYPE,
        is_request: false,
        version: spdm::Version::MANTICORE,
    });
    log::info!("serializing {}", type_name::<Cmd::Req>());
    req.to_wire(&mut writer)?;
    writer.finish(&mut conn)?;

    log::info!("waiting for response");
    let (header, len) = net::SpdmHeader::from_tcp(&mut conn)?;
    let mut r = TcpReader { tcp: conn, len };

    if header.command == <Cmd::Resp as Message>::TYPE {
        log::info!("deserializing {}", type_name::<Cmd::Resp>());
        Ok(Ok(FromWire::from_wire(&mut r, arena)?))
    } else if header.command == spdm::CommandType::Error {
        log::info!("deserializing {}", type_name::<protocol::Error<'a, Cmd>>());
        Ok(Err(fail!(FromWire::from_wire(&mut r, arena)?)))
    } else {
        Err(net::Error::BadHeader.into())
    }
}

/// Helper struct for exposing a TCP stream as a Manticore reader.
struct TcpReader {
    tcp: TcpStream,
    len: usize,
}
impl io::Read for TcpReader {
    fn read_bytes(&mut self, out: &mut [u8]) -> Result<(), io::Error> {
        let Self { tcp, len } = self;
        if *len < out.len() {
            return Err(fail!(io::Error::BufferExhausted));
        }
        tcp.read_exact(out).map_err(|e| {
            log::error!("{}", e);
            io::Error::Internal
        })?;
        *len -= out.len();
        Ok(())
    }

    fn remaining_data(&self) -> usize {
        self.len
    }
}
#[allow(unsafe_code)]
unsafe impl io::ReadZero<'_> for TcpReader {}

/// A header for a X-over-TCP protocol.
pub trait Header: net::Header {
    /// Reads a header and a length for the rest of the message off of the wire.
    fn from_tcp(r: impl std::io::Read) -> Result<(Self, usize), net::Error>;

    /// Writes the given header, and buffered output message, to the wire.
    fn to_tcp(
        self,
        msg: &[u8],
        w: impl std::io::Write,
    ) -> Result<(), net::Error>;
}

impl Header for net::CerberusHeader {
    fn from_tcp(
        mut r: impl std::io::Read,
    ) -> Result<(Self, usize), net::Error> {
        let mut header_bytes = [0u8; 3];
        r.read_exact(&mut header_bytes).map_err(|e| {
            log::error!("{}", e);
            net::Error::Io(io::Error::Internal)
        })?;
        let [cmd_byte, len_lo, len_hi] = header_bytes;

        let header = Self {
            command: cerberus::CommandType::from_wire_value(cmd_byte)
                .ok_or_else(|| {
                    log::error!("bad command byte: {}", cmd_byte);
                    net::Error::BadHeader
                })?,
        };
        let len = u16::from_le_bytes([len_lo, len_hi]);
        Ok((header, len as usize))
    }

    fn to_tcp(
        self,
        msg: &[u8],
        mut w: impl std::io::Write,
    ) -> Result<(), net::Error> {
        let [len_lo, len_hi] = (msg.len() as u16).to_le_bytes();
        w.write_all(&[self.command.to_wire_value(), len_lo, len_hi])
            .map_err(|e| {
                log::error!("{}", e);
                io::Error::BufferExhausted
            })?;
        w.write_all(msg).map_err(|e| {
            log::error!("{}", e);
            io::Error::BufferExhausted
        })?;
        Ok(())
    }
}

impl Header for net::SpdmHeader {
    fn from_tcp(
        mut r: impl std::io::Read,
    ) -> Result<(Self, usize), net::Error> {
        let mut header_bytes = [0u8; 4];
        r.read_exact(&mut header_bytes).map_err(|e| {
            log::error!("{}", e);
            net::Error::Io(io::Error::Internal)
        })?;
        let [len_lo, len_hi, version, cmd_byte] = header_bytes;
        let len = u16::from_le_bytes([len_lo, len_hi]);
        let len = len.checked_sub(4).ok_or_else(|| {
            log::error!("len too short: {}", len);
            net::Error::BadHeader
        })?;

        let header = Self {
            command: spdm::CommandType::from_wire_value(cmd_byte & 0x7f)
                .ok_or_else(|| {
                    log::error!("bad command byte: {:#04x}", cmd_byte);
                    net::Error::BadHeader
                })?,
            is_request: cmd_byte & 0x80 != 0,
            version: version.into(),
        };
        Ok((header, len as usize))
    }

    fn to_tcp(
        self,
        msg: &[u8],
        mut w: impl std::io::Write,
    ) -> Result<(), net::Error> {
        let [len_lo, len_hi] = (msg.len() as u16 + 4).to_le_bytes();
        let cmd_byte =
            ((self.is_request as u8) << 7) | self.command.to_wire_value();
        let version = self.version.byte();

        w.write_all(&[len_lo, len_hi, version, cmd_byte])
            .map_err(|e| {
                log::error!("{}", e);
                io::Error::BufferExhausted
            })?;
        w.write_all(msg).map_err(|e| {
            log::error!("{}", e);
            io::Error::BufferExhausted
        })?;
        Ok(())
    }
}

/// A helper for constructing X-over-TCP messages, for `X in [Cerberus, Spdm]`.
///
/// Because an X-over-TCP header requires a length prefix for the payload,
/// we need to buffer the entire reply before writing the header.
///
/// This type implements [`manticore::io::Write`].
struct Writer<H> {
    header: H,
    buf: Vec<u8>,
}

impl<H: Header> Writer<H> {
    /// Creates a new `Writer` that will encode the given abstract `header`.
    pub fn new(header: H) -> Self {
        Self {
            header,
            buf: Vec::new(),
        }
    }

    /// Flushes the buffered data to the given [`std::io::Write`] (usually, a
    /// [`TcpStream`]).
    pub fn finish(self, w: impl std::io::Write) -> Result<(), net::Error> {
        self.header.to_tcp(&self.buf, w)
    }
}

impl<H> io::Write for Writer<H> {
    fn write_bytes(&mut self, buf: &[u8]) -> Result<(), io::Error> {
        self.buf.extend_from_slice(buf);
        Ok(())
    }
}

/// A Cerberus-over-TCP implementation of [`HostPort`].
///
/// This type can be used to drive a Manticore server using a TCP port bound to
/// `localhost`. It also serves as an example for how an integration should
/// implement [`HostPort`] for their own transport.
pub struct TcpHostPort<H = net::CerberusHeader>(Inner<H>);

/// The "inner" state of the `HostPort`. This type is intended to carry the state
/// and functionality for an in-process request/response flow, without making it
/// accessible to outside callers except through the associated [`manticore::net`]
/// trait objects.
///
/// Most implementations of `HostPort` will follow this "nesting doll" pattern.
///
/// This type implements [`HostRequest`], [`HostReply`], and [`manticore::io::Read`],
/// though users may only move from one trait implementation to the other by calling
/// methods like `reply()` and `payload()`.
struct Inner<H> {
    listener: TcpListener,
    // State for `HostRequest`: a parsed header, the length of the payload, and
    // a stream to read it from.
    stream: Option<(H, usize, TcpStream)>,
    // State for `HostResponse`: a `Writer` to dump the response bytes into.
    output_buffer: Option<Writer<H>>,
}

impl<H> TcpHostPort<H> {
    /// Binds a new `TcpHostPort` to an open port.
    pub fn bind() -> Result<Self, net::Error> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| {
            log::error!("{}", e);
            net::Error::Io(io::Error::Internal)
        })?;
        Ok(Self(Inner {
            listener,
            stream: None,
            output_buffer: None,
        }))
    }

    /// Returns the TCP port this `HostPort` is bound to.
    pub fn port(&self) -> u16 {
        self.0.listener.local_addr().unwrap().port()
    }
}

impl<'req, H: Header + 'req> HostPort<'req, H> for TcpHostPort<H> {
    fn receive(&mut self) -> Result<&mut dyn HostRequest<'req, H>, net::Error> {
        let inner = &mut self.0;
        inner.stream = None;

        log::info!("blocking on listener");
        let (mut stream, _) = inner.listener.accept().map_err(|e| {
            log::error!("{}", e);
            net::Error::Io(io::Error::Internal)
        })?;

        log::info!("parsing header");
        let (header, len) = H::from_tcp(&mut stream)?;
        inner.stream = Some((header, len, stream));

        Ok(inner)
    }
}

impl<'req, H: Header + 'req> HostRequest<'req, H> for Inner<H> {
    fn header(&self) -> Result<H, net::Error> {
        if self.output_buffer.is_some() {
            log::error!("header() called out-of-order");
            return Err(fail!(net::Error::OutOfOrder));
        }
        self.stream
            .as_ref()
            .map(|(h, _, _)| *h)
            .ok_or_else(|| fail!(net::Error::Disconnected))
    }

    fn payload(&mut self) -> Result<&mut dyn io::ReadZero<'req>, net::Error> {
        if self.stream.is_none() {
            log::error!("payload() called out-of-order");
            return Err(fail!(net::Error::Disconnected));
        }
        if self.output_buffer.is_some() {
            log::error!("payload() called out-of-order");
            return Err(fail!(net::Error::OutOfOrder));
        }

        Ok(self)
    }

    fn reply(
        &mut self,
        header: H,
    ) -> Result<&mut dyn HostResponse<'req>, net::Error> {
        if self.stream.is_none() {
            log::error!("payload() called out-of-order");
            return Err(fail!(net::Error::Disconnected));
        }
        if self.output_buffer.is_some() {
            log::error!("payload() called out-of-order");
            return Err(fail!(net::Error::OutOfOrder));
        }

        self.output_buffer = Some(Writer::new(header));
        Ok(self)
    }
}

impl<'req, H: Header + 'req> HostResponse<'req> for Inner<H> {
    fn sink(&mut self) -> Result<&mut dyn io::Write, net::Error> {
        if self.stream.is_none() {
            log::error!("sink() called out-of-order");
            return Err(fail!(net::Error::Disconnected));
        }

        self.output_buffer
            .as_mut()
            .map(|w| w as &mut dyn io::Write)
            .ok_or_else(|| fail!(net::Error::OutOfOrder))
    }

    fn finish(&mut self) -> Result<(), net::Error> {
        match self {
            Inner {
                stream: Some((_, _, stream)),
                output_buffer: Some(_),
                ..
            } => {
                log::info!("sending reply");
                self.output_buffer.take().unwrap().finish(&mut *stream)?;
                stream.flush().map_err(|e| {
                    log::error!("{}", e);
                    net::Error::Io(io::Error::Internal)
                })?;
                self.stream = None;
                self.output_buffer = None;
                Ok(())
            }
            _ => Err(fail!(net::Error::Disconnected)),
        }
    }
}

impl<H> io::Read for Inner<H> {
    fn read_bytes(&mut self, out: &mut [u8]) -> Result<(), io::Error> {
        let (_, len, stream) =
            self.stream.as_mut().ok_or(io::Error::Internal)?;
        check!(*len >= out.len(), io::Error::BufferExhausted);
        stream.read_exact(out).map_err(|e| {
            log::error!("{}", e);
            io::Error::Internal
        })?;
        *len -= out.len();
        Ok(())
    }

    fn remaining_data(&self) -> usize {
        self.stream.as_ref().map(|(_, len, _)| *len).unwrap_or(0)
    }
}
#[allow(unsafe_code)]
unsafe impl<'a, H: 'a> io::ReadZero<'a> for Inner<H> {}
