# Deploying veilproof-server

The server needs three things: a Postgres database, a trusted setup, and the
knowledge that its setup matches the circuit registered on-chain.

The third is the one that bites. Without `VEILPROOF_VK_SHA256` the server will
start happily on the wrong keys — including the insecure development setup —
and answer `/health` with `ok` while every proof it produces is rejected by
veilproof-registry with `ProofInvalid`. Set the pin.

## Configuration

| Variable | Required | Meaning |
| -------- | -------- | ------- |
| `DATABASE_URL` | yes | Postgres connection string |
| `VEILPROOF_BIND` | no | listen address (default `0.0.0.0:8080`) |
| `VEILPROOF_KEYS_URL` | one of these | base URL serving `pk.bin` and `vk.bin`, fetched at boot |
| `VEILPROOF_KEYS_DIR` | one of these | directory holding `pk.bin` and `vk.bin` |
| `VEILPROOF_VK_SHA256` | strongly recommended | expected verifying-key digest; refuses to start on a mismatch |
| `RUST_LOG` | no | tracing filter |

If neither key variable is set the server falls back to the **insecure**
deterministic development setup. It says so loudly in the logs, but a log line
is easy to miss — the pin turns it into a failed boot.

### Testnet demo values

The keys behind the testnet deployment are published as a release asset,
matching the `membership` circuit registered on
`CC4IXULTDJ5OPE2YOBNIROD2HME2VA7QNK2NDCIUQQ453PZGFZVDMJFR`:

```sh
VEILPROOF_KEYS_URL=https://github.com/veilproof/veilproof-server/releases/download/keys-testnet
VEILPROOF_VK_SHA256=85d36192c03cb9240eeb03cb6a7c8dd954fac43ca31955e01fadd2b58f827218
```

Publishing a proving key is normal for Groth16 — it is public, and the scheme's
soundness never rested on keeping it secret. Only the setup's toxic waste must
be destroyed. Those particular keys were generated single-party, so they are
suitable for a testnet demo and nothing else; see the trusted-setup section of
the [README](README.md).

## Fly.io

`fly.toml` is in the repo. One machine is kept warm rather than scaled to zero,
so a reviewer following a link does not pay a cold start.

```sh
fly auth login
fly apps create veilproof-server          # or: fly launch --no-deploy
fly postgres create --name veilproof-db   # then attach, which sets DATABASE_URL
fly postgres attach veilproof-db --app veilproof-server
fly deploy
```

`fly.toml` already carries the keys URL and the digest pin.

## Render

`render.yaml` is a blueprint: point Render at this repo, and it builds the
Dockerfile, provisions Postgres, and injects `DATABASE_URL`.

Render's free web services sleep after inactivity and take roughly a minute to
wake. That is survivable for a demo, but if the link needs to answer promptly
every time, use a paid instance type or Fly.

## Any Docker host

```sh
docker build -t veilproof-server .
docker run -p 8080:8080 \
  -e DATABASE_URL=postgres://… \
  -e VEILPROOF_KEYS_URL=https://github.com/veilproof/veilproof-server/releases/download/keys-testnet \
  -e VEILPROOF_VK_SHA256=85d36192c03cb9240eeb03cb6a7c8dd954fac43ca31955e01fadd2b58f827218 \
  veilproof-server
```

Locally, `docker compose up` mounts `./keys` instead and reads the pin from
`.env`.

## Your own trusted setup

For anything beyond a demo, generate your own and register it on your own
registry deployment:

```sh
cargo run --release --bin veilproof-keygen -- ./keys   # prints the verifying key
cargo run --release --bin veilproof-vk -- ./keys       # prints it again, plus the digest
```

Pass the printed verifying key to `register_circuit`, and set the printed
`VEILPROOF_VK_SHA256` on the server. The two are then checked against each other
at every boot.

## Verifying a deployment

```sh
curl -s $URL/health     # {"status":"ok"} — the database is reachable
curl -s $URL/version    # name and version of the running build
curl -s $URL/issuers    # [] on a fresh database
```

Then check the logs say `loaded trusted-setup keys` and
`verifying key matches VEILPROOF_VK_SHA256`. A `DEVELOPMENT trusted setup`
warning means the keys never loaded and proofs will be rejected on-chain.
