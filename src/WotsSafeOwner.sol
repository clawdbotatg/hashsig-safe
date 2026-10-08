// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Wots} from "./Wots.sol";

interface ISafe {
    enum Operation {
        Call,
        DelegateCall
    }

    function approveHash(bytes32 hashToApprove) external;
    function nonce() external view returns (uint256);
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool success);
}

/// @notice A Safe owner that signs with hash-based one-time keys (WOTS) instead of ECDSA.
///
///         Add this contract as an owner of a Safe. Each approval reveals one
///         one-time signature and commits to the next public key, so every key
///         signs exactly once. Anyone can relay — the signature is bound to one
///         Safe tx hash, so a relayer can only submit it, not change it.
///
///         The relayer's EOA pays gas. If ECDSA breaks, the relayer loses gas
///         money, not the Safe.
contract WotsSafeOwner {
    bytes32 public constant DOMAIN = keccak256("WotsSafeOwner.v1");

    /// keccak256 of the current one-time public key (the 67 chain ends).
    bytes32 public pkHash;
    /// Index of the current one-time key. Goes up by one per approval.
    uint64 public nonce;

    event Approved(address indexed safe, bytes32 indexed safeTxHash, uint64 nonce, bytes32 nextPkHash);
    event ExecFailed(address indexed safe, bytes32 indexed safeTxHash);

    error BadSignature();
    error ZeroNextKey();

    constructor(bytes32 initialPkHash) {
        if (initialPkHash == bytes32(0)) revert ZeroNextKey();
        pkHash = initialPkHash;
    }

    /// The digest the one-time key signs.
    function digest(address safe, bytes32 safeTxHash, bytes32 nextPkHash) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN, block.chainid, address(this), safe, nonce, safeTxHash, nextPkHash));
    }

    /// Verify, burn the current key, approve the hash on the Safe. Never fails
    /// once the signature is valid, so a revealed key is always consumed.
    function approve(address safe, bytes32 safeTxHash, bytes32 nextPkHash, bytes32[67] calldata sig) public {
        if (nextPkHash == bytes32(0)) revert ZeroNextKey();
        uint64 k = nonce;
        if (Wots.recover(digest(safe, safeTxHash, nextPkHash), k, sig) != pkHash) revert BadSignature();
        pkHash = nextPkHash;
        nonce = k + 1;
        emit Approved(safe, safeTxHash, k, nextPkHash);
        ISafe(safe).approveHash(safeTxHash);
    }

    /// Approve and execute in one tx (threshold-1 Safe, no gas refund).
    /// If the Safe call fails the approval still stands; anyone can execute
    /// it later with a v = 1 signature for this owner.
    function approveAndExec(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        ISafe.Operation operation,
        bytes32 nextPkHash,
        bytes32[67] calldata sig
    ) external returns (bool ok) {
        bytes32 h = _safeTxHash(safe, to, value, data, operation);
        approve(safe, h, nextPkHash, sig);
        ok = _exec(safe, to, value, data, operation);
        if (!ok) emit ExecFailed(safe, h);
    }

    function _safeTxHash(address safe, address to, uint256 value, bytes calldata data, ISafe.Operation operation)
        internal
        view
        returns (bytes32)
    {
        uint256 n = ISafe(safe).nonce();
        return ISafe(safe).getTransactionHash(to, value, data, operation, 0, 0, 0, address(0), address(0), n);
    }

    function _exec(address safe, address to, uint256 value, bytes calldata data, ISafe.Operation operation)
        internal
        returns (bool ok)
    {
        bytes memory sigs = approvedSignature();
        try ISafe(safe).execTransaction(to, value, data, operation, 0, 0, 0, address(0), payable(address(0)), sigs)
        returns (bool s) {
            ok = s;
        } catch {}
    }

    /// Safe signature bytes for "this owner approved the hash" (v = 1).
    function approvedSignature() public view returns (bytes memory) {
        return abi.encodePacked(uint256(uint160(address(this))), bytes32(0), uint8(1));
    }
}
