// Used by test/Ffi.t.sol to prove the JS signer matches the contract.
//   node ffi.mjs pk <seed> <k>          -> abi-encoded bytes32
//   node ffi.mjs sign <seed> <k> <m>    -> abi-encoded bytes32[67]
import { encodeAbiParameters } from "viem";
import { pkHash, sign } from "./wots.mjs";

const [cmd, seed, k, m] = process.argv.slice(2);
if (cmd === "pk") process.stdout.write(encodeAbiParameters([{ type: "bytes32" }], [pkHash(seed, Number(k))]));
else if (cmd === "sign") process.stdout.write(encodeAbiParameters([{ type: "bytes32[67]" }], [sign(seed, Number(k), m)]));
