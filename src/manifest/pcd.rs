// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! The Platform Configuration Descriptor (PCD)
//!
//! The PCD is a signed configuration file describing what devices are
//! connected to an ROT and how to talk to them.
//!
//! The [`ParsedPcd`] type is the entry-point for this module.

use core::time::Duration;

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;
use zerocopy::Unaligned;

use crate::crypto::hash;
use crate::manifest;
use crate::manifest::provenance;
use crate::manifest::provenance::Provenance;
use crate::manifest::Container;
use crate::manifest::Error;
use crate::manifest::Manifest;
use crate::manifest::ManifestType;
use crate::manifest::Parse;
use crate::manifest::ParsedManifest;
use crate::manifest::TocEntry;
use crate::manifest::ValidationTime;
use crate::mem::misalign_of;
use crate::mem::Arena;

wire_enum! {
    /// A PCD element type.
    pub enum ElementType: u8 {
        /// Configuration options for the RoT a PCD is loaded into. In other
        /// words, it refers to the "self" RoT.
        SelfRot = 0x40,

        /// Configuration for a remote SPI flash device.
        SpiFlash = 0x41,

        /// Configuration for an I2C-connected Power Management Controller
        /// (PMC).
        I2cPmc = 0x42,

        /// Configuration for a remote RoT connected over direct I2C.
        DirectI2cComponent = 0x43,

        /// Configuration for a remote RoT connected over an MCTP bridge.
        BridgedMctpComponent = 0x44,
    }
}

/// A Platform Configuration Descriptor.
///
/// This type provides functions for parsing a PCD's table of contents and
/// using it to extract other portions of the PCD.
///
/// This type only maintains the TOC in memory for book-keeping.
pub struct ParsedPcd<'pcd, Provenance = provenance::Signed> {
    container: Container<'pcd, Pcd, Provenance>,
}

/// A [`Manifest`] implementation mapping onto [`ParsedPcd`], for use in generic
/// contexts.
///
/// See [`Manifest`] and [`Parse`].
pub enum Pcd {}

impl Manifest for Pcd {
    type ElementType = ElementType;
    const TYPE: ManifestType = ManifestType::Pcd;

    fn min_version(_: ElementType) -> u8 {
        0
    }
}

impl<'f, P> Parse<'f, P> for Pcd {
    type Parsed = ParsedPcd<'f, P>;

    fn parse(container: Container<'f, Self, P>) -> Result<Self::Parsed, Error> {
        Ok(ParsedPcd::new(container))
    }

    fn container(manifest: &Self::Parsed) -> &Container<'f, Self, P> {
        &manifest.container
    }

    type Guarded = ();
    fn validate(
        _manifest: &Self::Parsed,
        _when: ValidationTime,
        _args: &Self::Guarded,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<P> ParsedManifest for ParsedPcd<'_, P> {
    type Manifest = Pcd;
}

impl<'pcd, P> ParsedPcd<'pcd, P> {
    /// Creates a new PCD handle using the given `Container`.
    pub fn new(container: Container<'pcd, Pcd, P>) -> Self {
        ParsedPcd { container }
    }
}

impl<'pcd, P: Provenance> ParsedPcd<'pcd, P> {
    /// Extracts the `SelfRot` element from this PCD.
    ///
    /// This function will also verify the hash of the `SelfRot` if one
    /// is present.
    pub fn self_rot(
        &self,
        hasher: &mut dyn hash::Engine,
        arena: &'pcd dyn Arena,
    ) -> Result<Option<SelfRot<'_, 'pcd, P>>, Error> {
        let entry =
            match self.container.toc().singleton(ElementType::SelfRot.into()) {
                Some(x) => x,
                None => return Ok(None),
            };

        let (data, _) = entry.read_with_header::<SelfRotData, P>(
            self.container.flash(),
            arena,
            hasher,
        )?;

        Ok(Some(SelfRot {
            pcd: self,
            data,
            entry,
        }))
    }

    /// Extracts the `I2cPmc` element from this PCD.
    ///
    /// This function will also verify the hash of the `I2cPmc` if one
    /// is present.
    pub fn i2c_pmc(
        &self,
        hasher: &mut dyn hash::Engine,
        arena: &'pcd dyn Arena,
    ) -> Result<Option<I2cPort<'pcd>>, Error> {
        let entry =
            match self.container.toc().singleton(ElementType::I2cPmc.into()) {
                Some(x) => x,
                None => return Ok(None),
            };

        let (header, rest) = entry.read_with_header::<I2cPortHeader, P>(
            self.container.flash(),
            arena,
            hasher,
        )?;

        let mux_count = (header.flags >> 4) as usize;
        let (muxes, _) =
            LayoutVerified::<_, [I2cMux]>::new_slice_unaligned_from_prefix(
                rest, mux_count,
            )
            .ok_or(Error::TooShort {
                toc_index: entry.index(),
            })?;

        Ok(Some(I2cPort {
            header,
            muxes: muxes.into_slice(),
        }))
    }

    /// Returns an iterator over the `Component` elements of this PCD.
    ///
    /// The returned values only contain the `Toc` information for the entry,
    /// allowing the user to lazily select which entries to read from flash.
    pub fn components(
        &self,
    ) -> impl Iterator<Item = ComponentEntry<'_, 'pcd, P>> {
        use manifest::ElementType::Specific;
        self.container
            .toc()
            .entries()
            .filter(|e| {
                matches!(
                    e.element_type(),
                    Some(Specific(ElementType::DirectI2cComponent))
                        | Some(Specific(ElementType::BridgedMctpComponent))
                )
            })
            .map(move |entry| ComponentEntry { pcd: self, entry })
    }
}

/// Configuration options for the RoT a PCD is loaded into.
///
/// This also includes a list of flash devices directly connected to the RoT.
///
/// Note: this specific element describes an MCTP-flavored RoT; the name may
/// change in the future to reflect this.
pub struct SelfRot<'a, 'pcd, Provenance = provenance::Signed> {
    pcd: &'a ParsedPcd<'pcd, Provenance>,
    data: &'pcd SelfRotData,
    entry: TocEntry<'a, 'pcd, Pcd>,
}

/// The raw representation of `SelfRot` in memory.
#[derive(Clone, Copy, Debug, FromBytes, AsBytes)]
#[repr(C)]
struct SelfRotData {
    flags: u8,
    port_count: u8,
    component_count: u8,
    addr: u8,
    eid: u8,
    bridge_addr: u8,
    bridge_eid: u8,
    _reserved: [u8; 1],
}

/// A Cerberus RoT type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RotType {
    /// A Platform Root of Trust, i.e., a Pa-RoT.
    Platform,
    /// An Active Root of Trust, i.e., an Ac-RoT.
    Active,
}

impl<'a, 'pcd, P> SelfRot<'a, 'pcd, P> {
    /// Returns the `Toc` entry defining this element.
    pub fn entry(&self) -> TocEntry<'a, 'pcd, Pcd> {
        self.entry
    }

    /// Returns this RoT's type.
    pub fn rot_type(&self) -> RotType {
        match self.data.flags & 1 {
            0 => RotType::Platform,
            1 => RotType::Active,
            _ => unreachable!(),
        }
    }

    /// Returns total number of flash ports on this RoT.
    pub fn flash_ports(&self) -> usize {
        self.data.port_count as usize
    }

    /// Returns the total number of component RoTs connected to this RoT.
    pub fn components(&self) -> usize {
        self.data.component_count as usize
    }

    /// Returns this RoT's I2C address.
    pub fn rot_addr(&self) -> u8 {
        self.data.addr
    }

    /// Returns this RoT's MCTP endpoint ID.
    pub fn rot_eid(&self) -> u8 {
        self.data.eid
    }

    /// Returns the MCTP bridge's I2C address.
    pub fn bridge_addr(&self) -> u8 {
        self.data.bridge_addr
    }

    /// Returns the MCTP bridge's endpoint ID.
    pub fn bridge_eid(&self) -> u8 {
        self.data.bridge_eid
    }

    /// Returns an iterator over the `SpiFlash` elements of this PCD.
    ///
    /// The returned values only contain the `Toc` information for the entry,
    /// allowing the user to lazily select which entries to read from flash.
    pub fn spi_flashes(
        &self,
    ) -> impl Iterator<Item = SpiFlashEntry<'_, 'pcd, P>> {
        self.entry()
            .children_of(ElementType::SpiFlash.into())
            .map(move |entry| SpiFlashEntry { rot: self, entry })
    }
}

/// A [`SpiFlash`] element entry in a PCD's `Toc`.
///
/// This type allows for lazily reading the [`SpiFlash`] described by this
/// entry, as obtained from [`SelfRot::spi_flashes()`].
pub struct SpiFlashEntry<'a, 'pcd, Provenance = provenance::Signed> {
    rot: &'a SelfRot<'a, 'pcd, Provenance>,
    entry: TocEntry<'a, 'pcd, Pcd>,
}

impl<'a, 'pcd, P: Provenance> SpiFlashEntry<'a, 'pcd, P> {
    /// Returns the `Toc` entry defining this element.
    pub fn entry(&self) -> TocEntry<'a, 'pcd, Pcd> {
        self.entry
    }

    /// Reads the contents of this element into memory, verifying its hash
    /// and potentially allocating it on `arena`.
    pub fn read(
        self,
        hasher: &mut dyn hash::Engine,
        arena: &'pcd dyn Arena,
    ) -> Result<&'pcd SpiFlash, Error> {
        let (sf, _) = self.entry.read_with_header::<SpiFlash, P>(
            self.rot.pcd.container.flash(),
            arena,
            hasher,
        )?;
        Ok(sf)
    }
}

/// A flash device that can be accessed over SPI.
#[derive(Clone, Copy, Debug, FromBytes, AsBytes)]
#[repr(C)]
pub struct SpiFlash {
    port_id: u8,
    port_flags: u8,
    // The usage of this byte is currently not specified.
    _policy: u8,
    pulse_interval: u8,
    spi_freq: u32,
}

/// A SPI flash device mode.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpiFlashMode {
    Dual,
    Single,
    DualFiltered,
    SingleFiltered,
}

/// A SPI flash reset policy setting.
///
/// This setting describes what to do with a port's reset line when the flash
/// is being verified with respect to a PFM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpiResetPolicy {
    /// The RoT should notify the device of pending verification.
    Notify,
    /// The RoT should hold the device in reset during verification.
    Hold,
    /// The RoT should pulse the device's reset for the given duration after
    /// verification completes.
    Pulse(Duration),
}

impl SpiFlash {
    /// Returns this flash device's port ID.
    pub fn port_id(&self) -> u8 {
        self.port_id
    }

    /// Returns the reset policy for verification, if there is one.
    pub fn reset_policy(&self) -> Option<SpiResetPolicy> {
        match self.port_flags & 0b11 {
            0 => Some(SpiResetPolicy::Notify),
            1 => Some(SpiResetPolicy::Hold),
            // pulse_interval is in units of 10ms.
            2 => Some(SpiResetPolicy::Pulse(
                Duration::from_millis(self.pulse_interval as _) * 10,
            )),
            _ => None,
        }
    }

    /// Returns the operation mode for this flash device.
    pub fn mode(&self) -> Option<SpiFlashMode> {
        match (self.port_flags >> 2) & 0b11 {
            0 => Some(SpiFlashMode::Dual),
            1 => Some(SpiFlashMode::Single),
            2 => Some(SpiFlashMode::DualFiltered),
            3 => Some(SpiFlashMode::SingleFiltered),
            _ => None,
        }
    }

    /// Returns whether this device supports runtime verification.
    ///
    /// (Semantics currently not defined by Cerberus.)
    pub fn has_runtime_verification(&self) -> bool {
        (self.port_flags >> 4) & 1 == 1
    }

    /// Returns whether this device supports watchdog monitoring.
    ///
    /// (Semantics currently not defined by Cerberus.)
    pub fn has_watchdog(&self) -> bool {
        (self.port_flags >> 5) & 1 == 1
    }

    /// Returns the SPI frequency used by this device.
    ///
    /// (Units currently not specified by Cerberus.)
    pub fn frequency(&self) -> u32 {
        self.spi_freq
    }
}

/// An I2C port that the RoT may be connected to.
pub struct I2cPort<'pcd> {
    header: &'pcd I2cPortHeader,
    muxes: &'pcd [I2cMux],
}

impl I2cPort<'_> {
    /// Returns the I2C address of this port.
    pub fn addr(&self) -> u8 {
        self.header.addr
    }

    /// Returns the MCTP endpoint ID associated with the device at the other
    /// end of this port.
    pub fn eid(&self) -> u8 {
        self.header.eid
    }

    /// Returns a slice of muxes associated with this port.
    pub fn muxes(&self) -> &[I2cMux] {
        self.muxes
    }
}

#[derive(Clone, Copy, Debug, FromBytes, AsBytes, Unaligned)]
#[repr(C)]
struct I2cPortHeader {
    // The low four bits are flags that are currently unused.
    flags: u8,
    bus: u8,
    addr: u8,
    eid: u8,
}

/// An I2C multiplexer.
///
/// Field values' semantics currently not specified by Cerberus.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, FromBytes, AsBytes, Unaligned)]
#[repr(C)]
pub struct I2cMux {
    pub addr: u8,
    pub channel: u8,
}

/// A [`Component`] element entry in a PCD's `Toc`.
///
/// This type allows for lazily reading the [`Component`] described by this
/// entry, as obtained from [`ParsedPcd::components()`].
pub struct ComponentEntry<'a, 'pcd, Provenance = provenance::Signed> {
    pcd: &'a ParsedPcd<'pcd, Provenance>,
    entry: TocEntry<'a, 'pcd, Pcd>,
}

impl<'a, 'pcd, P: Provenance> ComponentEntry<'a, 'pcd, P> {
    /// Returns the `Toc` entry defining this element.
    pub fn entry(&self) -> TocEntry<'a, 'pcd, Pcd> {
        self.entry
    }

    /// Reads the contents of this element into memory, verifying its hash
    /// and potentially allocating it on `arena`.
    pub fn read(
        self,
        hasher: &mut dyn hash::Engine,
        arena: &'pcd dyn Arena,
    ) -> Result<Component<'pcd>, Error> {
        let (header, rest) =
            self.entry.read_with_header::<ComponentHeader, P>(
                self.pcd.container.flash(),
                arena,
                hasher,
            )?;

        if rest.len() < header.type_len as usize {
            return Err(Error::TooShort {
                toc_index: self.entry.index(),
            });
        }
        let (type_str, mut buf) = rest.split_at(header.type_len as usize);

        // Align back to 4-byte boundary.
        buf = buf.get(misalign_of(buf.as_ptr() as usize, 4)..).ok_or(
            Error::TooShort {
                toc_index: self.entry.index(),
            },
        )?;

        use manifest::ElementType::Specific;
        let connection = match self.entry.element_type() {
            Some(Specific(ElementType::DirectI2cComponent)) => {
                let (header, rest) =
                    LayoutVerified::<_, I2cPortHeader>::new_unaligned_from_prefix(buf)
                      .ok_or(Error::TooShort { toc_index: self.entry.index() })?;

                let mux_count = (header.flags >> 4) as usize;
                let (muxes, _) =
                    LayoutVerified::<_, [I2cMux]>::new_slice_unaligned_from_prefix(
                        rest, mux_count,
                    )
                    .ok_or(Error::TooShort {
                        toc_index: self.entry.index(),
                    })?;

                Connection::DirectI2c(I2cPort {
                    header: header.into_ref(),
                    muxes: muxes.into_slice(),
                })
            }

            Some(Specific(ElementType::BridgedMctpComponent)) => {
                let (bridge, _) =
                    LayoutVerified::<_, MctpBridge>::new_unaligned_from_prefix(
                        buf,
                    )
                    .ok_or(Error::TooShort {
                        toc_index: self.entry.index(),
                    })?;
                Connection::BridgedMctp(bridge.into_ref())
            }

            _ => return Err(Error::OutOfRange),
        };

        Ok(Component {
            header,
            type_str,
            connection,
        })
    }
}

/// A board component with an RoT that can be challenged.
pub struct Component<'pcd> {
    header: &'pcd ComponentHeader,
    type_str: &'pcd [u8],
    connection: Connection<'pcd>,
}

impl<'pcd> Component<'pcd> {
    /// Returns information about power control for this component.
    pub fn power_control(&self) -> ComponentPowerControl {
        self.header.power_ctrl
    }

    /// Returns a string that identifies the type of device this component is,
    /// for keying against a CFM.
    pub fn type_str(&self) -> &[u8] {
        self.type_str
    }

    /// Returns connection information for this component.
    pub fn connection(&self) -> &Connection<'pcd> {
        &self.connection
    }
}

/// A connection type that a [`Component`] might be reachable by.
#[allow(missing_docs)]
pub enum Connection<'pcd> {
    DirectI2c(I2cPort<'pcd>),
    BridgedMctp(&'pcd MctpBridge),
}

#[derive(Clone, Copy, Debug, FromBytes, AsBytes)]
#[repr(C)]
struct ComponentHeader {
    // The usage of this byte is currently not specified.
    _policy: u8,
    power_ctrl: ComponentPowerControl,
    type_len: u8,
}

/// Power control information for a [`Component`].
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, FromBytes, AsBytes)]
#[repr(C)]
pub struct ComponentPowerControl {
    pub register: u8,
    pub mask: u8,
}

/// An MCTP bridge (such as a BMC) that components might be connected over.
#[derive(Clone, Copy, Debug, FromBytes, AsBytes, Unaligned)]
#[repr(C)]
pub struct MctpBridge {
    _mctp_id: [u8; 8],
    _component_count: u8,
    eid: u8,
    _reserved: [u8; 2],
}

impl MctpBridge {
    /// Returns the MCTP endpoint ID for the bridge.
    pub fn eid(&self) -> u8 {
        self.eid
    }
}
