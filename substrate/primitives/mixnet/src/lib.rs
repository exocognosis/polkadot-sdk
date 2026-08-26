// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Substrate mixnet types and runtime interface.

#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod crypto_suite;
pub mod registration;
pub mod runtime_api;
pub mod types;

pub use crypto_suite::{
	ActiveSuite, CryptoSuiteId, PacketGeometry, PacketVersion, ScheduledSuiteActivation,
	VersionedAuthorityId, VersionedAuthoritySignature, VersionedKemPublicKey,
	VersionedPeerIdentity,
};
pub use registration::{
	RegistrationPayloadError, VersionedMixnode, VersionedRegistrationPayload,
	MAX_EXTERNAL_ADDRESSES, MAX_EXTERNAL_ADDRESSES_TOTAL_SIZE, MAX_EXTERNAL_ADDRESS_SIZE,
};
