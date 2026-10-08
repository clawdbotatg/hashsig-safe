// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Wots} from "../src/Wots.sol";

/// Test-only signer. Mirrors signer/wots.mjs.
/// Chain i of key k starts at keccak256(seed ‖ uint64 k ‖ uint16 i).
contract WotsSigner {
    bytes32 immutable seed;

    constructor(bytes32 _seed) {
        seed = _seed;
    }

    function secret(uint64 k, uint256 i) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(seed, k, uint16(i)));
    }

    function walk(bytes32 x, uint64 k, uint256 i, uint256 from, uint256 to) internal pure returns (bytes32) {
        for (uint256 j = from; j < to; ++j) x = Wots.step(x, k, i, j);
        return x;
    }

    function pkHash(uint64 k) external view returns (bytes32) {
        bytes32[67] memory ends;
        for (uint256 i; i < 67; ++i) ends[i] = walk(secret(k, i), k, i, 0, 15);
        return keccak256(abi.encodePacked(ends));
    }

    function sign(bytes32 m, uint64 k) external view returns (bytes32[67] memory sig) {
        uint8[67] memory d = Wots.digits(m);
        for (uint256 i; i < 67; ++i) sig[i] = walk(secret(k, i), k, i, 0, d[i]);
    }
}
