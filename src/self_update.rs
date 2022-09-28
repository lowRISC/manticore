// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! RoT self-update support.
//!
//! Cerberus provides a mechanism for an RoT to receive signed firmware
//! updates. This module implements the relevant functionality for
//! supporting this feature.

wire_enum! {
    /// A status reported by the firmware update service.
    pub enum UpdateStatus: u8 {
        /// The operation was successful.
        Success = 0x00,
        /// The operation is starting.
        Starting = 0x01,
        /// The operation failed to start.
        StartingFailed = 0x02,
        /// The received firmware image is being verified.
        Verifying = 0x03,
        /// Receiving the firmware image failed.
        RecieptFailed = 0x04,
        /// Verification of the received image failed.
        VerifyingFailed = 0x05,
        /// The received image is invalid.
        ImageInvalid = 0x06,
        /// The active image is being backed up.
        BackingUpActive = 0x07,
        /// Backing up the active image failed.
        BackingUpActiveFailed = 0x08,
        /// The application state is being saved.
        SavingAppState = 0x09,
        /// Saving the application state failed.
        SavingAppStateFailed = 0x0a,
        /// The active image is being updated with the staged image.
        UpdatingActiveWithStaged = 0x0b,
        /// Updating the active image failed.
        UpdatingActiveWithStagedFailed = 0x0c,
        /// Checking whether any certificates have been revoked.
        CheckingRevocations = 0x0d,
        /// Checking for certificate revocations failed.
        CheckingRecovationsFailed = 0x0e,
        /// Checking whether updates are required for the recovery image.
        CheckingRequiredUpdates = 0x0f,
        /// Checking for required updates failed.
        CheckingRequiredUpdatedFailed = 0x10,
        /// The recovery image is being backed up.
        BackingUpRecovery = 0x11,
        /// Backing up the recovery image failed.
        BackingUpRecoveryFailed = 0x12,
        /// The active image is being updated with the staged image.
        UpdatingRecoveryWithStaged = 0x13,
        /// Updating the recovery image failed.
        UpdatingRecoveryWithStagedFailed = 0x14,
        /// The previous certificate is being revoked.
        RevokingCert = 0x15,
        /// Certificate revocation failed.
        RevokingCertFailed = 0x16,
        /// No update operation occured since the last reboot.
        NoUpdateSinceLastReboot = 0x17,
        /// Preparing the staging area failed.
        PreparingStagingAreaFailed = 0x18,
        /// The staging area is being prepared to receive update data.
        PreparingStagingArea = 0x19,
        /// Writing data to the staging area field.
        WritingStagingAreaFailed = 0x1a,
        /// Update data is being written to the staging area.
        WritingStagingArea = 0x1b,
        /// A request was received before the previous operation completed.
        OutOfOrderRequest = 0x1c,
        /// The update service isn't running.
        ServiceNotRunning = 0x1d,
        /// The current status couldn't be determined.
        Indeterminate = 0x1e,
        /// Update operations are not currently permitted.
        NotPermitted = 0x1f,
    }
}
