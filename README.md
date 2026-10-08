# hashsig-safe

A Safe owner that signs with hash-based signatures instead of elliptic curves.
If ECDSA breaks, a Safe owned only by this contract stays safe.

**Unaudited. Experimental. Don't put real money in it yet.**

## How it works

- `WotsSafeOwner` is a contract you add as a Safe owner.
- It holds one **one-time** public key (Winternitz, w=16, keccak256).
- Each approval reveals one signature and sets the next public key. Each key signs once.
- The signature covers the Safe tx hash, the Safe, the chain, and the next key. A relayer can submit it but can't change it.
- Whoever sends the tx pays gas from a normal account. If ECDSA breaks, they lose gas money, not the Safe.

Gas: ~280k for `approve`, ~360k for `approveAndExec`. Signature is 67 × 32 bytes.

## Use

```bash
cd signer && npm i
node cli.mjs init                       # new seed in ./.wots/seed, prints initialPkHash
```

1. Deploy `WotsSafeOwner(initialPkHash)`.
2. Make it the Safe's **only** owner, threshold 1. Any ECDSA owner left on the Safe can be forged.
3. For each tx: get the Safe tx hash and `owner.nonce()`, then:

```bash
node cli.mjs sign --chain-id 1 --owner <WotsSafeOwner> --safe <Safe> --safe-tx-hash <hash> --nonce <n>
```

4. Anyone calls `approve(safe, safeTxHash, nextPkHash, sig)` (or `approveAndExec(...)` with the tx fields).
   After `approve`, anyone can execute the Safe tx with `owner.approvedSignature()` as the signatures.

## Rules

- **Never sign two different things with the same key index.** That leaks the key. `cli.mjs` records each signed digest in `.wots/state.json` and refuses a second one. Don't lose or roll back that file.
- If a tx fails, resubmit the **same** signature. `approve` consumes the key even if the Safe call later fails.
- Back up `.wots/seed` offline. It derives every key.
- Want a backup? Add a second `WotsSafeOwner` with a different seed and use threshold 1.

## Test

```bash
forge test        # includes an ffi test that the JS signer matches the contract
```
