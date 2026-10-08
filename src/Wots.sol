// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Winternitz one-time signatures (WOTS, w = 16) over keccak256.
///         Hash-only: no elliptic curves, no lattices.
///
///         A message digest is split into 64 base-16 digits plus a 3-digit
///         checksum = 67 hash chains. Each chain is 15 steps long.
///         Signer reveals step d of chain i; verifier hashes the rest of the way
///         to the end and compares against the public key.
///
///         ONE-TIME: a key that signs two different digests can be forged.
library Wots {
    uint256 internal constant W = 16;
    uint256 internal constant LEN1 = 64; // 256 bits / 4 bits per digit
    uint256 internal constant LEN = 67; // + 3 checksum digits (max checksum 960 < 16^3)

    /// One step of chain `i` for key `k`, moving from position `j` to `j + 1`.
    /// Key index + chain index + position are mixed in so every hash call is unique.
    function step(bytes32 x, uint64 k, uint256 i, uint256 j) internal pure returns (bytes32 r) {
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, x)
            mstore(add(p, 0x20), shl(192, k)) // 8 bytes
            mstore8(add(p, 0x28), shr(8, i)) // 2 bytes chain index
            mstore8(add(p, 0x29), i)
            mstore8(add(p, 0x2a), j) // 1 byte position
            r := keccak256(p, 0x2b)
        }
    }

    /// Base-16 digits of `m` (high nibble first) followed by the checksum digits.
    function digits(bytes32 m) internal pure returns (uint8[LEN] memory d) {
        uint256 csum;
        for (uint256 i; i < LEN1; ++i) {
            uint8 v = uint8(uint256(m) >> (252 - 4 * i)) & 0x0f;
            d[i] = v;
            csum += (W - 1) - v;
        }
        d[64] = uint8(csum >> 8) & 0x0f;
        d[65] = uint8(csum >> 4) & 0x0f;
        d[66] = uint8(csum) & 0x0f;
    }

    /// Public key hash that `sig` claims for digest `m` under key index `k`.
    /// Caller compares this to the stored public key hash.
    function recover(bytes32 m, uint64 k, bytes32[LEN] calldata sig) internal pure returns (bytes32) {
        uint8[LEN] memory d = digits(m);
        bytes32[LEN] memory ends;
        for (uint256 i; i < LEN; ++i) {
            bytes32 x = sig[i];
            for (uint256 j = d[i]; j < W - 1; ++j) {
                x = step(x, k, i, j);
            }
            ends[i] = x;
        }
        return keccak256(abi.encodePacked(ends));
    }
}
