// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A TCP-based Manticore `HostPort`.
//!
//! This specific binding of Manticore implements the abstract Cerberus header
//! as a four-bytes, consisting of, in order:
//! 1. The command type byte.
//! 2. The request bit; `0` for responses, `1` for requests.
//! 3. The length of the payload as a little-endian `u16`.

use std::any::type_name;
use std::io::Read as _;
use std::io::Write as _;
use std::net::TcpListener;
use std::net::TcpStream;

use manticore::io;
use manticore::mem::Arena;
use manticore::net;
use manticore::net::HostPort;
use manticore::net::HostRequest;
use manticore::net::HostResponse;
use manticore::protocol;
use manticore::protocol::wire::FromWire;
use manticore::protocol::wire::ToWire;
use manticore::protocol::wire::WireEnum;
use manticore::protocol::Command;
use manticore::protocol::CommandType;
use manticore::protocol::Header;
use manticore::protocol::Request;
use manticore::protocol::Response;
use manticore::server;

pub fn send_local<'a, Cmd, A>(
    port: u16,
    req: Cmd::Req,
    arena: &'a A,
) -> Result<Result<Cmd::Resp, protocol::Error>, server::Error>
where
    Cmd: Command<'a>,
    A: Arena,
{
    log::info!("connecting to 127.0.0.1:{}", port);
    let mut conn = TcpStream::connect(("127.0.0.1", port)).map_err(|e| {
        log::error!("{}", e);
        net::Error::Io(io::Error::Internal)
    })?;
    let mut writer = Writer::new(Header {
        command: <Cmd::Req as Request>::TYPE,
        is_request: true,
    });
    log::info!("serializing {}", type_name::<Cmd::Req>());
    req.to_wire(&mut writer)?;
    writer.finish(&mut conn)?;

    /// Helper struct for exposing a TCP stream as a Manticore reader.
    struct Reader<'a>(&'a mut TcpStream, usize);
    impl io::Read for Reader<'_> {
        fn read_bytes(&mut self, out: &mut [u8]) -> Result<(), io::Error> {
            let Reader(stream, len) = self;
            if *len < out.len() {
                return Err(io::Error::BufferExhausted);
            }
            stream.read_exact(out).map_err(|e| {
                log::error!("{}", e);
                io::Error::Internal
            })?;
            *len -= out.len();
            Ok(())
        }

        fn remaining_data(&self) -> usize {
            self.1
        }
    }
    log::info!("waiting for response");
    let (header, len) = header_from_wire(&mut conn)?;
    let r = Reader(&mut conn, len);

    if header.is_request {
        log::error!("unexpected header.is_request: {}", header.is_request);
        return Err(net::Error::BadHeader.into());
    }
    if header.command == <Cmd::Resp as Response>::TYPE {
        log::info!("deserializing {}", type_name::<Cmd::Resp>());
        Ok(Ok(FromWire::from_wire(r, arena)?))
    } else if header.command == CommandType::Error {
        log::info!("deserializing {}", type_name::<protocol::Error>());
        Ok(Err(FromWire::from_wire(r, arena)?))
    } else {
        Err(net::Error::BadHeader.into())
    }
}

fn header_from_wire(
    mut r: impl std::io::Read,
) -> Result<(Header, usize), net::Error> {
    let mut header_bytes = [0u8; 4];
    r.read_exact(&mut header_bytes).map_err(|e| {
        log::error!("{}", e);
        net::Error::Io(io::Error::Internal)
    })?;
    let [cmd_byte, req_bit, len_lo, len_hi] = header_bytes;

    let header = Header {
        command: CommandType::from_wire_value(cmd_byte).ok_or_else(|| {
            log::error!("bad command byte: {}", cmd_byte);
            net::Error::BadHeader
        })?,
        is_request: match req_bit {
            0 => false,
            1 => true,
            _ => {
                log::error!("bar request bit value: {}", req_bit);
                return Err(net::Error::BadHeader);
            }
        },
    };
    let len = u16::from_le_bytes([len_lo, len_hi]);
    Ok((header, len as usize))
}

pub struct Writer {
    header: Header,
    buf: Vec<u8>,
}

impl Writer {
    pub fn new(header: Header) -> Self {
        Self {
            header,
            buf: Vec::new(),
        }
    }

    pub fn finish(self, mut w: impl std::io::Write) -> Result<(), net::Error> {
        let [len_lo, len_hi] = (self.buf.len() as u16).to_le_bytes();
        w.write_all(&[
            self.header.command.to_wire_value(),
            self.header.is_request as u8,
            len_lo,
            len_hi,
        ])
        .map_err(|e| {
            log::error!("{}", e);
            net::Error::Io(io::Error::BufferExhausted)
        })?;
        w.write_all(&self.buf).map_err(|e| {
            log::error!("{}", e);
            net::Error::Io(io::Error::BufferExhausted)
        })?;
        Ok(())
    }
}

impl io::Write for Writer {
    fn write_bytes(&mut self, buf: &[u8]) -> Result<(), io::Error> {
        self.buf.extend_from_slice(buf);
        Ok(())
    }
}

pub struct TcpHostPort(Inner);

struct Inner {
    listener: TcpListener,
    stream: Option<(Header, usize, TcpStream)>,
    // This is currently necessary so that we know the full length of the
    // output a priori.
    output_buffer: Option<Writer>,
}

impl TcpHostPort {
    pub fn bind(port: u16) -> Result<Self, net::Error> {
        let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| {
            log::error!("{}", e);
            net::Error::Io(io::Error::Internal)
        })?;
        Ok(Self(Inner {
            listener,
            stream: None,
            output_buffer: None,
        }))
    }
}

impl HostPort for TcpHostPort {
    fn receive(&mut self) -> Result<&mut dyn HostRequest, net::Error> {
        let inner = &mut self.0;
        inner.stream = None;

        log::info!("blocking on listener");
        let (mut stream, _) = inner.listener.accept().map_err(|e| {
            log::error!("{}", e);
            net::Error::Io(io::Error::Internal)
        })?;

        log::info!("parsing header");
        let (header, len) = header_from_wire(&mut stream)?;
        inner.stream = Some((header, len, stream));

        Ok(inner)
    }
}

impl HostRequest for Inner {
    fn header(&self) -> Result<Header, net::Error> {
        if self.output_buffer.is_some() {
            log::error!("header() called out-of-order");
            return Err(net::Error::OutOfOrder);
        }
        self.stream
            .as_ref()
            .map(|(h, _, _)| *h)
            .ok_or(net::Error::Disconnected)
    }

    fn payload(&mut self) -> Result<&mut dyn io::Read, net::Error> {
        if self.stream.is_none() {
            log::error!("payload() called out-of-order");
            return Err(net::Error::Disconnected);
        }
        if self.output_buffer.is_some() {
            log::error!("payload() called out-of-order");
            return Err(net::Error::OutOfOrder);
        }

        Ok(self)
    }

    fn reply(
        &mut self,
        header: Header,
    ) -> Result<&mut dyn HostResponse, net::Error> {
        if self.stream.is_none() {
            log::error!("payload() called out-of-order");
            return Err(net::Error::Disconnected);
        }
        if self.output_buffer.is_some() {
            log::error!("payload() called out-of-order");
            return Err(net::Error::OutOfOrder);
        }

        self.output_buffer = Some(Writer::new(header));
        Ok(self)
    }
}

impl HostResponse for Inner {
    fn sink(&mut self) -> Result<&mut dyn io::Write, net::Error> {
        if self.stream.is_none() {
            log::error!("sink() called out-of-order");
            return Err(net::Error::Disconnected);
        }

        self.output_buffer
            .as_mut()
            .map(|w| w as &mut dyn io::Write)
            .ok_or(net::Error::OutOfOrder)
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
            _ => Err(net::Error::Disconnected),
        }
    }
}

impl io::Read for Inner {
    fn read_bytes(&mut self, out: &mut [u8]) -> Result<(), io::Error> {
        let (_, len, stream) =
            self.stream.as_mut().ok_or(io::Error::Internal)?;
        if *len < out.len() {
            return Err(io::Error::BufferExhausted);
        }
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
