// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Safe} from "safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {Enum} from "safe-smart-account/contracts/common/Enum.sol";
import {WotsSafeOwner, ISafe} from "../src/WotsSafeOwner.sol";
import {WotsSigner} from "./WotsSigner.sol";

contract WotsSafeOwnerTest is Test {
    Safe safe;
    WotsSafeOwner owner;
    WotsSigner signer;
    address bob = makeAddr("bob");
    address relayer = makeAddr("relayer");

    function setUp() public {
        signer = new WotsSigner(keccak256("test seed"));
        owner = new WotsSafeOwner(signer.pkHash(0));

        Safe singleton = new Safe();
        SafeProxyFactory factory = new SafeProxyFactory();
        address[] memory owners = new address[](1);
        owners[0] = address(owner);
        bytes memory init = abi.encodeCall(
            Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)))
        );
        safe = Safe(payable(address(factory.createProxyWithNonce(address(singleton), init, 0))));
        vm.deal(address(safe), 10 ether);
    }

    function _send(uint256 amount) internal {
        uint64 k = owner.nonce();
        bytes32 h = safe.getTransactionHash(bob, amount, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce());
        bytes32 next = signer.pkHash(k + 1);
        bytes32[67] memory sig = signer.sign(owner.digest(address(safe), h, next), k);
        vm.prank(relayer);
        assertTrue(owner.approveAndExec(address(safe), bob, amount, "", ISafe.Operation.Call, next, sig));
    }

    function test_sendEth() public {
        _send(1 ether);
        assertEq(bob.balance, 1 ether);
        assertEq(owner.nonce(), 1);
        assertEq(owner.pkHash(), signer.pkHash(1));
    }

    function test_manySends() public {
        for (uint256 i; i < 5; ++i) _send(0.1 ether);
        assertEq(bob.balance, 0.5 ether);
        assertEq(owner.nonce(), 5);
    }

    function test_twoStep_approveThenAnyoneExecutes() public {
        bytes32 h = safe.getTransactionHash(bob, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), 0);
        bytes32 next = signer.pkHash(1);
        owner.approve(address(safe), h, next, signer.sign(owner.digest(address(safe), h, next), 0));
        vm.prank(relayer);
        safe.execTransaction(bob, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), owner.approvedSignature());
        assertEq(bob.balance, 1 ether);
    }

    function test_relayerCannotChangeAmount() public {
        bytes32 h = safe.getTransactionHash(bob, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), 0);
        bytes32 next = signer.pkHash(1);
        bytes32[67] memory sig = signer.sign(owner.digest(address(safe), h, next), 0);
        vm.expectRevert(WotsSafeOwner.BadSignature.selector);
        owner.approveAndExec(address(safe), bob, 9 ether, "", ISafe.Operation.Call, next, sig);
    }

    function test_relayerCannotChangeNextKey() public {
        bytes32 h = safe.getTransactionHash(bob, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), 0);
        bytes32 next = signer.pkHash(1);
        bytes32[67] memory sig = signer.sign(owner.digest(address(safe), h, next), 0);
        vm.expectRevert(WotsSafeOwner.BadSignature.selector);
        owner.approve(address(safe), h, keccak256("attacker key"), sig);
    }

    function test_replayFails() public {
        bytes32 h = safe.getTransactionHash(bob, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), 0);
        bytes32 next = signer.pkHash(1);
        bytes32[67] memory sig = signer.sign(owner.digest(address(safe), h, next), 0);
        owner.approve(address(safe), h, next, sig);
        vm.expectRevert(WotsSafeOwner.BadSignature.selector);
        owner.approve(address(safe), h, next, sig);
    }

    function test_flippedSigElementFails() public {
        bytes32 h = safe.getTransactionHash(bob, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), 0);
        bytes32 next = signer.pkHash(1);
        bytes32[67] memory sig = signer.sign(owner.digest(address(safe), h, next), 0);
        for (uint256 i; i < 67; i += 11) {
            bytes32[67] memory bad = sig;
            bad[i] = bad[i] ^ bytes32(uint256(1));
            vm.expectRevert(WotsSafeOwner.BadSignature.selector);
            owner.approve(address(safe), h, next, bad);
        }
    }

    function test_wrongKeyFails() public {
        WotsSigner other = new WotsSigner(keccak256("other seed"));
        bytes32 h = safe.getTransactionHash(bob, 1 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), 0);
        bytes32 next = other.pkHash(1);
        bytes32[67] memory sig = other.sign(owner.digest(address(safe), h, next), 0);
        vm.expectRevert(WotsSafeOwner.BadSignature.selector);
        owner.approve(address(safe), h, next, sig);
    }

    function test_failedExecKeepsApproval() public {
        // Ask for more ETH than the Safe has: exec fails, key is still consumed, approval stays.
        uint64 k = owner.nonce();
        bytes32 h = safe.getTransactionHash(bob, 50 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), 0);
        bytes32 next = signer.pkHash(k + 1);
        bytes32[67] memory sig = signer.sign(owner.digest(address(safe), h, next), k);
        assertFalse(owner.approveAndExec(address(safe), bob, 50 ether, "", ISafe.Operation.Call, next, sig));
        assertEq(owner.nonce(), 1);
        assertEq(safe.approvedHashes(address(owner), h), 1);
        vm.deal(address(safe), 50 ether);
        safe.execTransaction(bob, 50 ether, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), owner.approvedSignature());
        assertEq(bob.balance, 50 ether);
    }
}
