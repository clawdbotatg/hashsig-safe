// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WotsSafeOwner} from "../src/WotsSafeOwner.sol";
import {WotsSigner} from "./WotsSigner.sol";

/// JS signer (signer/wots.mjs) must produce keys and signatures the contract accepts.
contract FfiTest is Test {
    bytes32 seed = keccak256("ffi seed");

    function _node(string memory cmd, uint64 k, bytes32 m) internal returns (bytes memory) {
        string[] memory c = new string[](6);
        c[0] = "node";
        c[1] = "signer/ffi.mjs";
        c[2] = cmd;
        c[3] = vm.toString(seed);
        c[4] = vm.toString(uint256(k));
        c[5] = vm.toString(m);
        return vm.ffi(c);
    }

    function test_jsMatchesSolidity() public {
        WotsSigner sol = new WotsSigner(seed);
        bytes32 pk0 = abi.decode(_node("pk", 0, 0), (bytes32));
        bytes32 pk1 = abi.decode(_node("pk", 1, 0), (bytes32));
        assertEq(pk0, sol.pkHash(0));

        WotsSafeOwner owner = new WotsSafeOwner(pk0);
        address safe = makeAddr("safe");
        vm.etch(safe, hex"00"); // approveHash call just needs code to not revert
        bytes32 h = keccak256("some safe tx");
        bytes32 m = owner.digest(safe, h, pk1);
        bytes32[67] memory sig = abi.decode(_node("sign", 0, m), (bytes32[67]));
        owner.approve(safe, h, pk1, sig);
        assertEq(owner.nonce(), 1);
    }
}
