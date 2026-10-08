// WOTS (w = 16) over keccak256. Must match src/Wots.sol byte for byte.
import { keccak256, encodePacked, encodeAbiParameters } from "viem";

export const LEN = 67;
const W = 16;

export const DOMAIN = keccak256(new TextEncoder().encode("WotsSafeOwner.v1"));

const step = (x, k, i, j) =>
  keccak256(encodePacked(["bytes32", "uint64", "uint16", "uint8"], [x, BigInt(k), i, j]));

const walk = (x, k, i, from, to) => {
  for (let j = from; j < to; j++) x = step(x, k, i, j);
  return x;
};

const secret = (seed, k, i) => keccak256(encodePacked(["bytes32", "uint64", "uint16"], [seed, BigInt(k), i]));

export function digits(m) {
  const hex = m.slice(2);
  const d = [];
  let csum = 0;
  for (let i = 0; i < 64; i++) {
    const v = parseInt(hex[i], 16);
    d.push(v);
    csum += W - 1 - v;
  }
  d.push((csum >> 8) & 15, (csum >> 4) & 15, csum & 15);
  return d;
}

export function pkHash(seed, k) {
  const ends = [];
  for (let i = 0; i < LEN; i++) ends.push(walk(secret(seed, k, i), k, i, 0, W - 1));
  return keccak256(encodePacked(Array(LEN).fill("bytes32"), ends));
}

export function sign(seed, k, m) {
  const d = digits(m);
  return d.map((di, i) => walk(secret(seed, k, i), k, i, 0, di));
}

// Same as WotsSafeOwner.digest().
export const digest = ({ chainId, owner, safe, nonce, safeTxHash, nextPkHash }) =>
  keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "uint256" },
        { type: "address" },
        { type: "address" },
        { type: "uint64" },
        { type: "bytes32" },
        { type: "bytes32" },
      ],
      [DOMAIN, BigInt(chainId), owner, safe, BigInt(nonce), safeTxHash, nextPkHash],
    ),
  );
