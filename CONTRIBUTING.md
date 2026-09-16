# Contributing to veilproof-server

Thanks for your interest. This service generates real zero-knowledge proofs, so
correctness of the cryptography comes before everything else — a subtly wrong
circuit or serialization is a security failure, not a bug.

## Ground rules

- **The `src/crypto` module is the trust-critical core.** Keep it small, keep it
  commented, and keep it exhaustively tested. Resist adding unrelated features
  there.
- **Never change the encoding by guesswork.** The byte layout must match what
  veilproof-registry's native BN254 host functions expect. If you touch
  `src/crypto/encoding.rs` or the circuit, the `reproduces_registry_accepted_vector`
  round-trip test must still pass — that test is the guarantee the output is
  byte-correct against a vector the contract is proven to accept.
- **Never store or log raw PII or holder secrets.** The server sees commitments
  and, transiently, secrets during proving. Secrets must not be persisted or
  written to logs. If you add logging near `/prove`, do not log the request body.
- **Keep the native and gadget hashes in lockstep.** `mimc::native_and_gadget_agree`
  guards this; if you change one side, change the other and keep the test green.

## Development

```sh
make check       # fmt-check + clippy -D warnings + test (what CI runs)
make test        # the crypto round-trip needs no database
make run         # run against a local Postgres (see .env.example)
make up          # server + postgres in containers
```

The round-trip test does not need a database. Handler/store work that does can
run Postgres via `docker compose up -d postgres`.

## Pull requests

- One focused change per PR, with a clear description of *why*.
- Add or update tests. A change to proving or encoding without a test that would
  have caught the regression is not ready.
- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`
  must all pass.
- Be honest in docs about what the server does and does not protect — see the
  README's security section. That honesty is part of the project's value.

## Good first issues

- Swap MiMC for Poseidon (keep the round-trip test passing against a regenerated
  registry vector).
- A background indexer to populate `generated_nullifiers` from on-chain events,
  so the cache reflects real on-chain use.
- Optional issuer-side on-chain submission (documented tradeoff: the server
  would then hold signing authority).
