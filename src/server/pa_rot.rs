// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A `manticore` "server" and "client" for a PA-RoT.
//!
//! This module provides structures for serving responses to a host making
//! requests to a PA-RoT.

use crate::crypto::rsa;
use crate::hardware;
use crate::mem::Arena;
use crate::net;
use crate::server::options::Options;
use crate::server::response::Respond;
use crate::server::rot::Rot;
use crate::server::Error;

/// A PA-RoT, or "Platform Root of Trust", server.
///
/// This type implements the request -> response "business logic" of the
/// host <-> PA-RoT interaction. That is, it accepts input and output buffers,
/// and from those, parses incoming requests and processes them into responses.
pub struct PaRot<'a, Identity, Reset, Rsa> {
    rot: Rot<'a, Identity, Reset, Rsa>,
}

impl<'a, Identity, Reset, Rsa> PaRot<'a, Identity, Reset, Rsa>
where
    Identity: hardware::Identity,
    Reset: hardware::Reset,
    Rsa: rsa::Builder,
{
    /// Create a new `PaRot` with the given `Options`.
    pub fn new(opts: Options<'a, Identity, Reset, Rsa>) -> Self {
        Self {
            rot: Rot::new(opts),
        }
    }
}

impl<'a, Identity, Reset, Rsa> Respond for PaRot<'a, Identity, Reset, Rsa>
where
    Identity: hardware::Identity,
    Reset: hardware::Reset,
    Rsa: rsa::Builder,
{
    fn process_request<'req>(
        &mut self,
        host_port: &mut dyn net::HostPort,
        arena: &'req impl Arena,
    ) -> Result<(), Error> {
        self.rot.process_request(host_port, arena)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::time::Duration;

    use crate::crypto::ring;
    use crate::hardware::fake;
    use crate::hardware::Identity as _;
    use crate::io::Cursor;
    use crate::mem::BumpArena;
    use crate::net::DevicePort;
    use crate::protocol;
    use crate::protocol::capabilities::*;
    use crate::protocol::device_id;
    use crate::protocol::wire::FromWire;
    use crate::protocol::wire::ToWire;
    use crate::protocol::Header;

    const NETWORKING: Networking = Networking {
        max_message_size: 1024,
        max_packet_size: 256,
        mode: RotMode::Platform,
        roles: BusRole::HOST,
    };

    const TIMEOUTS: Timeouts = Timeouts {
        regular: Duration::from_millis(30),
        crypto: Duration::from_millis(200),
    };

    const DEVICE_ID: device_id::DeviceIdentifier =
        device_id::DeviceIdentifier {
            vendor_id: 1,
            device_id: 2,
            subsys_vendor_id: 3,
            subsys_id: 4,
        };

    fn simulate_request<'a, C: protocol::Command<'a>, A: Arena>(
        scratch_space: &'a mut [u8],
        arena: &'a mut A,
        server: &mut PaRot<fake::Identity, fake::Reset, ring::rsa::Builder>,
        request: C::Req,
    ) -> Result<Result<C::Resp, protocol::Error>, Error> {
        use crate::protocol::Response;

        let len = scratch_space.len();
        let (req_scratch, port_scratch) = scratch_space.split_at_mut(len / 2);
        let mut cursor = Cursor::new(req_scratch);
        request
            .to_wire(&mut cursor)
            .expect("failed to write request");
        let request_bytes = cursor.take_consumed_bytes();

        let mut host_port = net::InMemHost::new(port_scratch);
        host_port.request(
            Header {
                is_request: true,
                command: <C::Req as protocol::Request<'a>>::TYPE,
            },
            request_bytes,
        );

        server.process_request(&mut host_port, arena)?;

        let (header, mut resp) = host_port.response().unwrap();
        assert!(!header.is_request);

        if header.command == protocol::Error::TYPE {
            let resp_val = FromWire::from_wire(&mut resp, arena)
                .expect("failed to read response");
            assert_eq!(resp.len(), 0);
            return Ok(Err(resp_val));
        }

        let resp_val = FromWire::from_wire(&mut resp, arena)
            .expect("failed to read response");
        assert_eq!(resp.len(), 0);
        Ok(Ok(resp_val))
    }

    fn simulate_response<'a, C: protocol::Command<'a>, A: Arena>(
        scratch_space: &'a mut [u8],
        arena: &'a mut A,
        request: C::Req,
    ) -> Result<C::Resp, Error> {
        let len = scratch_space.len();
        let (req_scratch, _port_scratch) = scratch_space.split_at_mut(len / 2);
        let mut cursor = Cursor::new(req_scratch);
        request
            .to_wire(&mut cursor)
            .expect("failed to write request");
        let request_bytes = cursor.take_consumed_bytes();

        let header = Header {
            is_request: true,
            command: <C::Req as protocol::Request<'a>>::TYPE,
        };

        // Create the DevicePort
        let mut device_port = net::InMemDevice::new();

        // Send a request to a device
        device_port.send(0x10, header, request_bytes).unwrap();

        // Fake the response
        device_port.response(
            Header {
                is_request: false,
                command: <C::Req as protocol::Request<'a>>::TYPE,
            },
            &[1, 0, 2, 0, 3, 0, 4, 0],
        );

        // Block until we receive a response
        device_port.wait_for_response(100)?;

        // Get the response
        let response = device_port.receive_response()?;

        assert_eq!(response.header().unwrap(), header);

        let payload = response.payload().unwrap();

        let resp_val = FromWire::from_wire(payload, arena)
            .expect("failed to read response");
        Ok(resp_val)
    }

    #[test]
    fn sanity() {
        let identity = fake::Identity::new(
            b"test version",
            &[(1, b"vendor fw 1"), (3, b"vendor fw 3")],
            b"random bits",
        );
        let reset = fake::Reset::new(0, Duration::from_millis(1));
        let rsa = ring::rsa::Builder::new();
        let mut server = PaRot::new(Options {
            identity: &identity,
            reset: &reset,
            rsa: &rsa,
            device_id: DEVICE_ID,
            networking: NETWORKING,
            timeouts: TIMEOUTS,
        });

        let mut scratch = [0; 1024];
        let mut arena = [0; 64];
        let mut arena = BumpArena::new(&mut arena);

        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 0 };
        let resp = simulate_request::<protocol::FirmwareVersion, _>(
            &mut scratch,
            &mut arena,
            &mut server,
            req,
        )
        .expect("got error from server")
        .expect("got error message from server");
        assert_eq!(resp.version, identity.firmware_version());

        arena.reset();

        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 1 };
        let resp = simulate_request::<protocol::FirmwareVersion, _>(
            &mut scratch,
            &mut arena,
            &mut server,
            req,
        )
        .expect("got error from server")
        .expect("got error message from server");
        assert_eq!(Some(resp.version), identity.vendor_firmware_version(1));

        arena.reset();

        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 2 };
        let resp = simulate_request::<protocol::FirmwareVersion, _>(
            &mut scratch,
            &mut arena,
            &mut server,
            req,
        )
        .expect("got error from server")
        .expect_err("got non-error message from server");
        assert_eq!(resp.code, protocol::ErrorCode::Unspecified);

        arena.reset();

        let req = protocol::device_id::DeviceIdRequest;
        let resp = simulate_request::<protocol::DeviceId, _>(
            &mut scratch,
            &mut arena,
            &mut server,
            req,
        )
        .expect("got error from server")
        .expect("got error message from server");
        assert_eq!(resp.id, DEVICE_ID);

        arena.reset();

        let req = protocol::device_id::DeviceIdRequest;
        let resp = simulate_response::<protocol::DeviceId, _>(
            &mut scratch,
            &mut arena,
            req,
        )
        .expect("got error from client");
        assert_eq!(resp.id, DEVICE_ID);
    }
}
