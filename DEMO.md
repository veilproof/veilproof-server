# A full run on Stellar testnet

Every step below was executed against the deployed contract. The transaction
hashes are real and can be opened on a block explorer.

- **Registry:** [`CC4IXULTDJ5OPE2YOBNIROD2HME2VA7QNK2NDCIUQQ453PZGFZVDMJFR`](https://stellar.expert/explorer/testnet/contract/CC4IXULTDJ5OPE2YOBNIROD2HME2VA7QNK2NDCIUQQ453PZGFZVDMJFR)
- **Circuit:** `membership`, registered with the [keys-testnet](https://github.com/veilproof/veilproof-server/releases/tag/keys-testnet) trusted setup
- **Credential:** `kyc`

## 1. A holder computes their commitment

Locally. The secret never leaves the holder's machine at this stage.

```sh
$ veilproof-commit
secret     = 0542…4377
commitment = 11f1…8c6d
```

## 2. The issuer builds a tree

Eight commitments, the holder's among them. The issuer sees commitments and
nothing else — no identity data reaches the server.

```sh
$ curl -X POST $API/issuers/kyc/leaves -d '{"commitment":"11f1…8c6d"}'
{"position":7,"count":8}
```

## 3. The issuer publishes the root on-chain

```sh
$ curl -X POST $API/issuers/kyc/publish
{"root":"2719f38b8028b3af0353170e9e676342998e970ebafea32b4777484f811f1d6a"}
```

Submitted by the issuer's own key — the server holds no signing authority:

> `publish_root` → [`92bf99b3…3ca5ca`](https://stellar.expert/explorer/testnet/tx/92bf99b3b0082aa82a89f79c827dff5147ef85e47e858c10ba7e4a24313ca5ca)
> `RootPublished`, root `2719f38b…1f1d6a`

## 4. The holder generates a proof

```sh
$ curl -X POST $API/issuers/kyc/prove \
    -d '{"secret":"0542…4377","holder_address":"GBUT…Q3WX"}'
{"proof":{"a":"24caa1b1…","b":"0105f1b3…","c":"070a2613…"},
 "root":"2719f38b…1f1d6a","nullifier":"1ccec994…cc7e"}
```

The root matches what is on-chain, byte for byte.

## 5. The contract verifies it

Groth16 verification via Soroban's native BN254 pairing check (CAP-0074):

> `verify_credential` → [`0f22eccd…808cda`](https://stellar.expert/explorer/testnet/tx/0f22eccdcf3c055f8c5f48177d1e1a46a9ba0f8da5944b7dff927c4a3a808cda)
> `CredentialVerified`, holder `GBUT…Q3WX`

```sh
$ stellar contract invoke … -- is_verified --holder GBUT…Q3WX --credential kyc
true
```

An address that never proved anything reads `false`.

## What the chain learned

That `GBUT…Q3WX` belongs to the issuer's `kyc` set. **Not** which of the nine
members it is, and nothing about a real-world identity. The contract saw only a
root, a nullifier, and an address.

## The two attacks, run for real

### Replaying a proof

Resubmitting an accepted proof:

```
Error(Contract, #8)   // NullifierUsed
```

The nullifier is deterministic in the holder's secret, so a second
verification for the same credential is refused no matter who sends it.

### Stealing a proof in transit

This is the one worth isolating, because the nullifier check would mask it. A
**second** holder proved membership, and their proof was intercepted before
submission — nullifier still unused. An attacker submitted those exact bytes
under their own address:

```
Error(Contract, #7)   // ProofInvalid
```

The same bytes, submitted by the holder they were generated for, were accepted:

> [`CredentialVerified`, holder `GDFY…DODO`](https://stellar.expert/explorer/testnet/contract/CC4IXULTDJ5OPE2YOBNIROD2HME2VA7QNK2NDCIUQQ453PZGFZVDMJFR)

The proof commits to the holder's address as a public input (`addr =
Fr(sha256(strkey) mod r)`, derived identically on both sides), so a proof is
worthless to anyone but its subject.

## What this does not show

- The trusted setup was generated **single-party**. If its toxic waste survived,
  membership proofs can be forged, and no on-chain evidence would reveal it. A
  production deployment needs a multi-party ceremony.
- The holder's secret is sent to the server to build the proof. The server does
  not store or log it, but that is a promise, not a guarantee — proving in the
  browser would remove the need to trust it. That is future work, and the
  dashboard says so rather than implying otherwise.
- Nothing here is audited.
