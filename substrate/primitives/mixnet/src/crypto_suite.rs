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

//! Versioned crypto-suite primitives for a staged mixnet migration.
//!
//! These types are additive. Existing V1 types and encodings remain unchanged.

use codec::{Decode, Encode};
use scale_info::TypeInfo;

/// X25519 public-key size.
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
/// Ed25519 public-key size.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// sr25519 public-key size.
pub const SR25519_PUBLIC_KEY_SIZE: usize = 32;
/// sr25519 signature size.
pub const SR25519_SIGNATURE_SIZE: usize = 64;
/// ML-KEM-768 public-key size from FIPS 203.
pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1_184;
/// ML-DSA-65 public-key size from FIPS 204.
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1_952;
/// ML-DSA-65 signature size from FIPS 204.
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3_309;

/// Current classical suite.
pub const V1_CLASSICAL: CryptoSuiteId = CryptoSuiteId(1);
/// Hybrid Category 3 suite.
pub const V2_HYBRID_CAT3: CryptoSuiteId = CryptoSuiteId(2);
/// Post-quantum-only Category 3 suite.
pub const V3_PQ_CAT3: CryptoSuiteId = CryptoSuiteId(3);

/// Identifier for one compiled crypto suite.
#[derive(Clone, Copy, Debug, Decode, Encode, TypeInfo, PartialEq, Eq, PartialOrd, Ord)]
pub struct CryptoSuiteId(pub u16);

/// Packet wire-format version.
#[derive(Clone, Copy, Debug, Decode, Encode, TypeInfo, PartialEq, Eq)]
pub struct PacketVersion(pub u8);

/// Fixed packet dimensions for one compiled suite.
#[derive(Clone, Copy, Debug, Decode, Encode, TypeInfo, PartialEq, Eq)]
pub struct PacketGeometry {
	/// Maximum route length.
	pub max_hops: u8,
	/// Application payload size in bytes.
	pub payload_size: u16,
	/// Complete packet size in bytes.
	pub packet_size: u16,
	/// Header MAC size in bytes.
	pub header_mac_size: u8,
	/// Payload integrity size in bytes.
	pub payload_integrity_size: u8,
}

/// Suite metadata compiled into the runtime and node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuiteDescriptor {
	/// Suite identifier.
	pub id: CryptoSuiteId,
	/// Packet version.
	pub packet_version: PacketVersion,
	/// Notification protocol name.
	pub protocol_name: &'static str,
	/// Fixed packet dimensions.
	pub geometry: PacketGeometry,
}

const V1_GEOMETRY: PacketGeometry = PacketGeometry {
	max_hops: 6,
	payload_size: 2_048,
	packet_size: 2_252,
	header_mac_size: 16,
	payload_integrity_size: 16,
};

const V2_GEOMETRY: PacketGeometry = PacketGeometry {
	max_hops: 6,
	payload_size: 2_048,
	packet_size: 9_060,
	header_mac_size: 32,
	payload_integrity_size: 32,
};

const V3_GEOMETRY: PacketGeometry = PacketGeometry {
	max_hops: 6,
	payload_size: 2_048,
	packet_size: 8_868,
	header_mac_size: 32,
	payload_integrity_size: 32,
};

static SUITES: [SuiteDescriptor; 3] = [
	SuiteDescriptor {
		id: V1_CLASSICAL,
		packet_version: PacketVersion(1),
		protocol_name: "/mixnet/1",
		geometry: V1_GEOMETRY,
	},
	SuiteDescriptor {
		id: V2_HYBRID_CAT3,
		packet_version: PacketVersion(2),
		protocol_name: "/mixnet/2",
		geometry: V2_GEOMETRY,
	},
	SuiteDescriptor {
		id: V3_PQ_CAT3,
		packet_version: PacketVersion(2),
		protocol_name: "/mixnet/2",
		geometry: V3_GEOMETRY,
	},
];

impl CryptoSuiteId {
	/// Resolve a suite through the closed registry.
	pub fn descriptor(self) -> Option<&'static SuiteDescriptor> {
		SUITES.iter().find(|suite| suite.id == self)
	}
}

/// Suite required by finalized chain state.
pub type ActiveSuite = CryptoSuiteId;

/// A future suite activation.
#[derive(Clone, Copy, Debug, Decode, Encode, TypeInfo, PartialEq, Eq)]
pub struct ScheduledSuiteActivation {
	/// Suite to activate.
	pub next_suite: CryptoSuiteId,
	/// First session that requires the suite.
	pub activation_session: u32,
}

/// Canonical packet KEM public key with an algorithm tag.
#[derive(Clone, Decode, Encode, TypeInfo, PartialEq, Eq)]
pub enum VersionedKemPublicKey {
	/// V1 X25519 key. The variant index and bytes preserve a separate V2 API.
	V1X25519([u8; X25519_PUBLIC_KEY_SIZE]),
	/// V2 key with both required KEM components.
	V2Hybrid {
		/// X25519 public key.
		x25519: [u8; X25519_PUBLIC_KEY_SIZE],
		/// ML-KEM-768 public key.
		ml_kem_768: [u8; ML_KEM_768_PUBLIC_KEY_SIZE],
	},
	/// V3 ML-KEM-768 key.
	V3MlKem768([u8; ML_KEM_768_PUBLIC_KEY_SIZE]),
}

/// Canonical peer identity with an algorithm tag.
#[derive(Clone, Decode, Encode, TypeInfo, PartialEq, Eq)]
pub enum VersionedPeerIdentity {
	/// V1 Ed25519 identity.
	V1Ed25519([u8; ED25519_PUBLIC_KEY_SIZE]),
	/// V2 locator and authoritative ML-DSA-65 identity.
	V2Hybrid {
		/// Ed25519 routing locator.
		ed25519_locator: [u8; ED25519_PUBLIC_KEY_SIZE],
		/// ML-DSA-65 authentication key.
		ml_dsa_65: [u8; ML_DSA_65_PUBLIC_KEY_SIZE],
	},
	/// V3 ML-DSA-65 identity.
	V3MlDsa65([u8; ML_DSA_65_PUBLIC_KEY_SIZE]),
}

/// Canonical authority identifier with an algorithm tag.
#[derive(Clone, Decode, Encode, TypeInfo, PartialEq, Eq)]
pub enum VersionedAuthorityId {
	/// V1 sr25519 authority key.
	V1Sr25519([u8; SR25519_PUBLIC_KEY_SIZE]),
	/// V2 authority keys.
	V2Hybrid {
		/// sr25519 authority key.
		sr25519: [u8; SR25519_PUBLIC_KEY_SIZE],
		/// ML-DSA-65 authority key.
		ml_dsa_65: [u8; ML_DSA_65_PUBLIC_KEY_SIZE],
	},
	/// V3 ML-DSA-65 authority key.
	V3MlDsa65([u8; ML_DSA_65_PUBLIC_KEY_SIZE]),
}

/// Canonical authority signature with an algorithm tag.
#[derive(Clone, Decode, Encode, TypeInfo, PartialEq, Eq)]
pub enum VersionedAuthoritySignature {
	/// V1 sr25519 signature.
	V1Sr25519([u8; SR25519_SIGNATURE_SIZE]),
	/// V2 signatures. Both fields are required.
	V2Hybrid {
		/// sr25519 signature.
		sr25519: [u8; SR25519_SIGNATURE_SIZE],
		/// ML-DSA-65 signature.
		ml_dsa_65: [u8; ML_DSA_65_SIGNATURE_SIZE],
	},
	/// V3 ML-DSA-65 signature.
	V3MlDsa65([u8; ML_DSA_65_SIGNATURE_SIZE]),
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn registry_rejects_unknown_suite() {
		assert!(CryptoSuiteId(0).descriptor().is_none());
		assert!(CryptoSuiteId(4).descriptor().is_none());
	}

	#[test]
	fn geometry_is_frozen() {
		assert_eq!(V1_CLASSICAL.descriptor().unwrap().geometry.packet_size, 2_252);
		assert_eq!(V2_HYBRID_CAT3.descriptor().unwrap().geometry.packet_size, 9_060);
		assert_eq!(V3_PQ_CAT3.descriptor().unwrap().geometry.packet_size, 8_868);
	}

	#[test]
	fn v1_suite_id_has_stable_scale_encoding() {
		assert_eq!(V1_CLASSICAL.encode(), [1, 0]);
		assert_eq!(CryptoSuiteId::decode(&mut &V1_CLASSICAL.encode()[..]).unwrap(), V1_CLASSICAL);
	}

	#[test]
	fn hybrid_key_encoding_has_fixed_length() {
		let key = VersionedKemPublicKey::V2Hybrid {
			x25519: [0; X25519_PUBLIC_KEY_SIZE],
			ml_kem_768: [0; ML_KEM_768_PUBLIC_KEY_SIZE],
		};
		assert_eq!(key.encode().len(), 1 + X25519_PUBLIC_KEY_SIZE + ML_KEM_768_PUBLIC_KEY_SIZE);
	}

	#[test]
	fn unknown_key_variant_fails_decode() {
		assert!(VersionedKemPublicKey::decode(&mut &[0xff][..]).is_err());
	}
}
