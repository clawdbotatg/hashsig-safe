#!/usr/bin/env node
// Offline WOTS signer for WotsSafeOwner. No network calls.
//
//   node cli.mjs init                      new seed, prints first public key hash
//   node cli.mjs pk [k]                    public key hash for key k (default 0)
//   node cli.mjs sign --chain-id 1 --owner 0x.. --safe 0x.. --safe-tx-hash 0x.. --nonce K
//
// State lives in --dir (default ./.wots): `seed` (SECRET) and `state.json`,
// which records the digest each key index signed. A key index will never sign
// a second, different digest — that is what keeps one-time keys safe.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { pkHash, sign, digest } from "./wots.mjs";

const args = process.argv.slice(2);
const cmd = args[0];
const opt = (name, def) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : def;
};
const dir = opt("dir", ".wots");
const seedFile = path.join(dir, "seed");
const stateFile = path.join(dir, "state.json");
const die = (msg) => {
  console.error(msg);
  process.exit(1);
};

const loadSeed = () => {
  if (!fs.existsSync(seedFile)) die(`no seed at ${seedFile} — run init`);
  return fs.readFileSync(seedFile, "utf8").trim();
};
const loadState = () => (fs.existsSync(stateFile) ? JSON.parse(fs.readFileSync(stateFile, "utf8")) : { signed: {} });

if (cmd === "init") {
  if (fs.existsSync(seedFile)) die(`${seedFile} already exists — refusing to overwrite`);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const seed = "0x" + crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(seedFile, seed + "\n", { mode: 0o600 });
  fs.writeFileSync(stateFile, JSON.stringify({ signed: {} }, null, 2));
  console.log(JSON.stringify({ initialPkHash: pkHash(seed, 0) }));
  console.error(`seed written to ${seedFile} — back it up offline, never commit it`);
} else if (cmd === "pk") {
  const k = Number(args[1] ?? 0);
  console.log(pkHash(loadSeed(), k));
} else if (cmd === "sign") {
  const seed = loadSeed();
  const k = Number(opt("nonce") ?? die("--nonce required (read owner.nonce() on-chain)"));
  const fields = {
    chainId: opt("chain-id") ?? die("--chain-id required"),
    owner: opt("owner") ?? die("--owner required"),
    safe: opt("safe") ?? die("--safe required"),
    safeTxHash: opt("safe-tx-hash") ?? die("--safe-tx-hash required"),
    nonce: k,
    nextPkHash: pkHash(seed, k + 1),
  };
  const m = digest(fields);
  const state = loadState();
  const prev = state.signed[k];
  if (prev && prev !== m) die(`key ${k} already signed a different digest (${prev}). Signing again would leak the key. Refusing.`);
  if (!prev) {
    state.signed[k] = m;
    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2)); // record BEFORE releasing the signature
  }
  console.log(JSON.stringify({ nonce: k, digest: m, nextPkHash: fields.nextPkHash, sig: sign(seed, k, m) }, null, 2));
} else {
  die("usage: cli.mjs init | pk [k] | sign --chain-id --owner --safe --safe-tx-hash --nonce [--dir]");
}
