# veilproof-server

The backend for **veilproof**, the Soroban zero-knowledge compliance-credential
suite. It lets issuers manage a Merkle tree of credential holders and publish
its root, and lets holders generate a Groth16 membership + nullifier proof they
can submit directly to the [veilproof-registry][registry] contract — without
the holder's identity or the tree's other members ever being exposed.

Generating a real, verifiable Groth16 proof (circuit design, trusted setup,
witness generation, Soroban-specific serialization) is specialist work. This
service does it behind a small HTTP API so issuers and holders don't have to.

## How it fits together

```
   issuer                         veilproof-server                 Soroban
   ------                         ----------------                 -------
   verify a holder off-chain
   → compute a commitment
     POST /issuers/{n}/leaves  ─▶ store commitment (a hash)
     POST /issuers/{n}/publish ─▶ recompute root ──▶ returns root ─▶ issuer submits
                                                                     publish_root(root)

   holder (knows their secret)
     POST /issuers/{n}/prove   ─▶ leaf = H(secret); find in tree;
       { secret }                 build witness; Groth16 prove;
                                  encode for Soroban
                              ◀─ { proof, root, nullifier } ───────▶ holder submits
                                                                     verify_credential(...)
```

The server sees **commitments and secrets, never real-world identities**, and
never links a leaf to a person. See [Security & privacy](#security--privacy).

## BN254 encoding (the crux)

A proof is useless unless its bytes match exactly what the contract's native
BN254 host functions expect. This server produces the **same CAP-0074 encoding
veilproof-registry documents and consumes** — verified against that repo's
README and cross-checked by a test (below). The rules, each the opposite of an
arkworks default:

| Element  | Encoding                                                       | Length    |
| -------- | ------------------------------------------------------------- | --------- |
| `Fp`/`Fr`| **big-endian** 32 bytes                                       | 32 bytes  |
| G1 point | `be(X) ‖ be(Y)` — **uncompressed**                            | 64 bytes  |
| G2 point | `be(X.c1) ‖ be(X.c0) ‖ be(Y.c1) ‖ be(Y.c0)` — **uncompressed**| 128 bytes |

arkworks serializes little-endian, often compressed, with Fp2 as `c0‖c1`, so
`src/crypto/encoding.rs` is an explicit conversion layer — nothing here relies
on arkworks' `CanonicalSerialize`. Full details and the CAP-0074 citation live
in the [registry README][registry-encoding].

### The round-trip test is the proof this is correct

`tests/round_trip.rs` is the centerpiece. `reproduces_registry_accepted_vector`
regenerates — byte-for-byte — the exact verifying key, proof, and public inputs
committed in veilproof-registry, whose CI proves Soroban's native
`pairing_check` accepts them. Reproducing those bytes ties this server's output
to output the real contract is demonstrated to accept. Run it:

```sh
cargo test --test round_trip
```

## Library choices

- **arkworks 0.5** (`ark-bn254`, `ark-groth16`, `ark-r1cs-std`, `ark-relations`)
  for BN254 + Groth16. `soroban-env-host` itself depends on `ark-bn254`, so the
  proving side and the on-chain verifier share the same curve arithmetic.
- **MiMC** as the in-circuit hash (`t^5` per round over the scalar field).
  Chosen because it is minimal enough to implement correctly in both native and
  gadget form, with a test (`mimc::native_and_gadget_agree`) proving the two
  match. Poseidon is the more common production choice and is tracked as future
  work — the point for the MVP is a correct, arithmetic-friendly hash.
- **axum** for HTTP, **sqlx** (Postgres) for storage, **serde**/**tracing** for
  the usual plumbing.

## Quickstart

```sh
# 1. Start Postgres (and the server) in containers:
cp .env.example .env
docker compose up --build          # server on :8080

# — or run the server against your own Postgres:
docker compose up -d postgres
export DATABASE_URL=postgres://veilproof:veilproof@localhost:5432/veilproof
cargo run

# 2. Exercise it (commitments/secrets are 64-hex-char field elements):
curl -X POST localhost:8080/issuers/kyc/leaves \
  -H 'content-type: application/json' \
  -d '{"commitment":"<64 hex chars>"}'
curl -X POST localhost:8080/issuers/kyc/publish     # → { "root": "..." }
curl -X POST localhost:8080/issuers/kyc/prove \
  -H 'content-type: application/json' \
  -d '{"secret":"<64 hex chars>","holder_address":"G..."}'  # → { proof, root, nullifier }
```

The commitment for a secret is `H(secret, LEAF_DOMAIN)` under the same MiMC
hash the circuit uses; see `crypto::leaf_commitment`.

## API reference

| Method & path                    | Body                    | Returns |
| -------------------------------- | ----------------------- | ------- |
| `GET  /health`                   | —                       | `{ "status": "ok" }` (503 if the DB is down) |
| `GET  /version`                  | —                       | `{ name, version }` |
| `GET  /issuers`                  | —                       | `{ "issuers": [name, ...] }` |
| `GET  /issuers/{name}`           | —                       | `{ name, leaf_count, capacity, published_root }` |
| `POST /issuers/{name}/leaves`    | `{ "commitment": hex }` | `{ "position", "count" }` |
| `POST /issuers/{name}/publish`   | —                       | `{ "root": hex }` |
| `GET  /issuers/{name}/root`      | —                       | `{ "root": hex }` (404 if never published) |
| `POST /issuers/{name}/prove`     | `{ "secret": hex, "holder_address": strkey }` | `{ "proof": {a,b,c}, "root", "nullifier" }` |

`prove` refuses if the tree has changed since the last `publish` (HTTP 409):
the proof's root is a public input the contract checks against its on-chain
root, so the server will not hand back a proof the contract would reject.

## Security & privacy

**What the server knows.** Only leaf **commitments** (hashes issuers compute
off-chain) and, transiently, a holder's **secret** and **address** while
building a proof. It never receives, stores, or logs raw PII, and it never
links a leaf to a real-world identity — that mapping stays with the issuer,
off-chain. The holder submits their secret directly to `/prove`; it is used to
derive public, non-identifying values and is then dropped.

**Proofs are address-bound.** `/prove` takes the holder's Stellar address and
binds it into the proof as a public input (`Fr(sha256(strkey) mod r)`, the same
derivation the contract performs on-chain). A proof therefore verifies only for
the address it was generated for, so one observed in transit cannot be replayed
by another party.

**What it does not protect.**

- **The development setup is insecure; a production path is provided.**
  `crypto::dev_keys` uses a fixed seed so the verifying key matches the
  registry's test vector — which means the toxic waste is public and anyone
  could forge proofs. For production, run `veilproof-keygen <dir>` to generate
  keys with the OS secure RNG (destroying the machine's state afterwards; a
  multi-party ceremony is stronger), deploy the registry with the verifying key
  it prints, and start the server with `VEILPROOF_KEYS_DIR=<dir>`. Without that
  variable the server falls back to the dev setup and logs a loud warning.
- **Soundness depends on the circuit**, which is shared with the registry. A
  flawed circuit produces proofs that verify but mean nothing; the server
  cannot detect that.
- **The server does not custody keys or submit transactions** for holders, and
  by default not for issuers either — publishing on-chain is the issuer's own
  responsibility. Submitting on an issuer's behalf would make the server hold
  signing authority and become a higher-value target; that path is
  intentionally out of the MVP.
- **The `generated_nullifiers` table is bookkeeping only.** A row means a proof
  was generated here, not that it was used on-chain — the contract is
  authoritative for on-chain nullifier state.

## Layout

```
src/crypto/      circuit, trusted setup, proving, Soroban encoding (the core)
src/merkle.rs    the Merkle tree
src/store.rs     Postgres persistence
src/api/         axum handlers — issuer.rs (tree mgmt), holder.rs (proving)
tests/           the round-trip centerpiece + unit tests
migrations/      Postgres schema
```

## Scope

One fixed circuit (Merkle-membership + nullifier). Deliberately **not** built:
multiple/arbitrary circuit types, a KYC/identity-verification pipeline (issuers
bring their own off-chain verification), and wallet/key custody for holders.

## License

Apache-2.0 — see [LICENSE](LICENSE).

[registry]: https://github.com/veilproof/veilproof-registry
[registry-encoding]: https://github.com/veilproof/veilproof-registry#bn254-encoding-notes
