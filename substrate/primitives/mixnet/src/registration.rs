// This file is part of Substrate.

// Copyright (C) 2026 Rick Glenn
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

//! Canonical mixnode registration payload for versioned suites.

use crate::crypto_suite::{
	CryptoSuiteId, PacketVersion, VersionedKemPublicKey, VersionedPeerIdentity,
};
use alloc::vec::Vec;
use codec::{Decode, Encode};
use scale_info::TypeInfo;

/// Domain tag covered by every V2 or V3 registration signature.
pub const REGISTRATION_DOMAIN_TAG: &[u8; 29] = b"pqc-sc-mixnet-registration-v2";
/// Maximum external addresses in one registration.
pub const MAX_EXTERNAL_ADDRESSES: usize = 8;
/// Maximum encoded bytes in one external address.
pub const MAX_EXTERNAL_ADDRESS_SIZE: usize = 256;
/// Maximum combined external-address bytes.
pub const MAX_EXTERNAL_ADDRESSES_TOTAL_SIZE: usize = 1_024;

/// A validated versioned mixnode record.
#[derive(Clone, Decode, Encode, TypeInfo, PartialEq, Eq)]
pub struct VersionedMixnode {
	/// Versioned packet KEM key.
	pub packet_kem_key: VersionedKemPublicKey,
	/// Versioned peer identity.
	pub peer_identity: VersionedPeerIdentity,
	/// Canonical external addresses.
	pub external_addresses: Vec<Vec<u8>>,
}

/// Fields covered by the authority registration signature.
#[derive(Clone, Decode, Encode, TypeInfo, PartialEq, Eq)]
pub struct VersionedRegistrationPayload {
	/// Fixed signing domain.
	pub domain_tag: [u8; REGISTRATION_DOMAIN_TAG.len()],
	/// Chain genesis hash.
	pub genesis_hash: [u8; 32],
	/// Pallet storage and call version.
	pub pallet_version: u16,
	/// Packet and registration protocol version.
	pub protocol_version: PacketVersion,
	/// Session being registered.
	pub session: u32,
	/// Authority index in the session.
	pub authority_index: u32,
	/// Required crypto suite.
	pub suite_id: CryptoSuiteId,
	/// Validated mixnode record.
	pub mixnode: VersionedMixnode,
}

/// Validation error for a versioned registration payload.
#[derive(Clone, Copy, Debug, Decode, Encode, TypeInfo, PartialEq, Eq)]
pub enum RegistrationPayloadError {
	/// The suite does not exist in the compiled registry.
	UnknownSuite,
	/// A key or identity form does not match the selected suite.
	SuiteMismatch,
	/// The registration has too many external addresses.
	TooManyExternalAddresses,
	/// One external address is too long.
	ExternalAddressTooLong,
	/// The combined external-address bytes are too large.
	ExternalAddressesTooLarge,
}

impl VersionedRegistrationPayload {
	/// Validate all bounds and construct the canonical signing payload.
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		genesis_hash: [u8; 32],
		pallet_version: u16,
		protocol_version: PacketVersion,
		session: u32,
		authority_index: u32,
		suite_id: CryptoSuiteId,
		packet_kem_key: VersionedKemPublicKey,
		peer_identity: VersionedPeerIdentity,
		external_addresses: Vec<Vec<u8>>,
	) -> Result<Self, RegistrationPayloadError> {
		if suite_id.descriptor().is_none() {
			return Err(RegistrationPayloadError::UnknownSuite);
		}
		if packet_kem_key.suite_id() != suite_id || peer_identity.suite_id() != suite_id {
			return Err(RegistrationPayloadError::SuiteMismatch);
		}
		if external_addresses.len() > MAX_EXTERNAL_ADDRESSES {
			return Err(RegistrationPayloadError::TooManyExternalAddresses);
		}
		if external_addresses
			.iter()
			.any(|address| address.len() > MAX_EXTERNAL_ADDRESS_SIZE)
		{
			return Err(RegistrationPayloadError::ExternalAddressTooLong);
		}
		let total_size = external_addresses
			.iter()
			.try_fold(0usize, |total, address| total.checked_add(address.len()))
			.ok_or(RegistrationPayloadError::ExternalAddressesTooLarge)?;
		if total_size > MAX_EXTERNAL_ADDRESSES_TOTAL_SIZE {
			return Err(RegistrationPayloadError::ExternalAddressesTooLarge);
		}
		Ok(Self {
			domain_tag: *REGISTRATION_DOMAIN_TAG,
			genesis_hash,
			pallet_version,
			protocol_version,
			session,
			authority_index,
			suite_id,
			mixnode: VersionedMixnode { packet_kem_key, peer_identity, external_addresses },
		})
	}

	/// Return the canonical SCALE bytes that both signatures must cover.
	pub fn signing_bytes(&self) -> Vec<u8> {
		self.encode()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto_suite::{
		ED25519_PUBLIC_KEY_SIZE, ML_DSA_65_PUBLIC_KEY_SIZE, ML_KEM_768_PUBLIC_KEY_SIZE,
		V1_CLASSICAL, V2_HYBRID_CAT3, X25519_PUBLIC_KEY_SIZE,
	};

	fn hybrid_payload() -> VersionedRegistrationPayload {
		VersionedRegistrationPayload::new(
			[1; 32],
			2,
			PacketVersion(2),
			42,
			3,
			V2_HYBRID_CAT3,
			VersionedKemPublicKey::V2Hybrid {
				x25519: [2; X25519_PUBLIC_KEY_SIZE],
				ml_kem_768: [3; ML_KEM_768_PUBLIC_KEY_SIZE],
			},
			VersionedPeerIdentity::V2Hybrid {
				ed25519_locator: [4; ED25519_PUBLIC_KEY_SIZE],
				ml_dsa_65: [5; ML_DSA_65_PUBLIC_KEY_SIZE],
			},
			vec![b"/ip4/127.0.0.1/tcp/30333".to_vec()],
		)
		.unwrap()
	}

	#[test]
	fn signing_bytes_cover_domain_and_all_fields() {
		let payload = hybrid_payload();
		let bytes = payload.signing_bytes();
		assert!(bytes.starts_with(REGISTRATION_DOMAIN_TAG));
		assert!(VersionedRegistrationPayload::decode(&mut &bytes[..]).unwrap() == payload);
	}

	#[test]
	fn suite_mismatch_fails() {
		let payload = VersionedRegistrationPayload::new(
			[1; 32],
			2,
			PacketVersion(2),
			42,
			3,
			V1_CLASSICAL,
			VersionedKemPublicKey::V2Hybrid {
				x25519: [2; X25519_PUBLIC_KEY_SIZE],
				ml_kem_768: [3; ML_KEM_768_PUBLIC_KEY_SIZE],
			},
			VersionedPeerIdentity::V1Ed25519([4; ED25519_PUBLIC_KEY_SIZE]),
			Vec::new(),
		);
		assert!(matches!(payload, Err(RegistrationPayloadError::SuiteMismatch)));
	}

	#[test]
	fn external_address_bounds_fail_closed() {
		let mut payload = hybrid_payload();
		payload.mixnode.external_addresses = vec![vec![0; MAX_EXTERNAL_ADDRESS_SIZE + 1]];
		let result = VersionedRegistrationPayload::new(
			payload.genesis_hash,
			payload.pallet_version,
			payload.protocol_version,
			payload.session,
			payload.authority_index,
			payload.suite_id,
			payload.mixnode.packet_kem_key,
			payload.mixnode.peer_identity,
			payload.mixnode.external_addresses,
		);
		assert!(matches!(result, Err(RegistrationPayloadError::ExternalAddressTooLong)));
	}
}
