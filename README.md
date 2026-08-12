# Axiom Protocol

Axiom is an experimental Solidity protocol for registering content provenance, managing identities and DIDs, issuing programmable licenses, resolving disputes, and testing privacy-preserving registration flows.

This repository is under active development. It has a substantial Foundry test suite, but it has not been presented here as externally audited or mainnet-ready. In particular, the checked-in Groth16 verifier contains a placeholder verification key and reports `PRODUCTION_READY = false`; privacy tests use a mock verifier.

## Architecture

Axiom uses a hybrid upgrade architecture:

```text
ERC1967Proxy
    -> AxiomRouter implementation (UUPS upgrade, roles, native pause/ERC-165)
        -> fallback selector routing
            -> Registry / Treasury / Identity / Access / DID
            -> License / Dispute / Privacy facets
        -> shared AxiomStorage under delegatecall
```

The facet dispatch resembles a Diamond, but it is not a complete EIP-2535 implementation: upgrades to the router use UUPS, while facet selectors are managed by custom admin functions rather than the standard `diamondCut` and loupe interfaces.

`script/AxiomSelectorManifest.sol` is the production selector source of truth used by deployment and tests. Router-native `supportsInterface(bytes4)`, `pause()`, and `unpause()` selectors are deliberately not facet-routed. Roadmap-only functions that still return placeholders or always revert are also excluded.

The legacy operator-only `disputeContent` shortcut remains in its implementation for compatibility but is not routed by fresh deployments. Production dispute state must move through the stake-backed Dispute facet lifecycle so it can be resolved and cleared consistently.

The legacy DID `nonce(address)` getter is likewise not routed: it has no consuming meta-transaction flow and must not be advertised as replay protection.

## Current module status

| Module | Current scope | Readiness notes |
| --- | --- | --- |
| Registry, Treasury, Identity, Access | Core registration, fee, identity, moderation, and configuration flows | Locally tested; no external audit claim |
| DID Registry | DID-inspired registration, delegates, verification levels, and attributes | Local implementation; standards interoperability is not certified |
| License | License templates, purchase/mint, transfers, ownership queries, direct payment splitting, and territory metadata | Deferred royalty claims and sublicensing are not in the routed production API |
| Dispute | Configurable staking, response/evidence, arbitration, timeout resolution, settlement, appeals, and stake claims | External arbitrator and token configurations require deployment-specific integration testing |
| Privacy | Commitments, nullifiers, ownership checks, and erasure workflow | Local/mock testing only until a real circuit, trusted setup, production verification key, and proof-generation client exist |

## Prerequisites

- Foundry. CI pins Foundry `v1.7.1`.
- Git with submodule support.
- An RPC endpoint and a Foundry keystore account only when deploying.

## Quick start

```bash
git clone --recurse-submodules https://github.com/RakanAji/AxiomProtocol.git
cd AxiomProtocol

forge fmt --check
forge build
forge test
```

If the repository was cloned without submodules:

```bash
git submodule update --init --recursive
```

Useful focused commands:

```bash
forge test --match-contract AxiomRouterTest
forge test --match-contract AxiomFacetTest
forge test --match-contract IntegrationTest
forge test --match-contract AxiomSelectorManifestTest
forge test --match-contract AxiomInvariant
forge coverage --ir-minimum --exclude-tests --report summary
```

## Deployment

`DeployPhase4` performs a fresh deployment of the ERC-1967 proxy and all eight facets, installs the canonical selector manifest, applies dispute configuration, and checks the resulting routes before the broadcast ends.

Simulate first, then add `--broadcast` only after reviewing the trace and environment:

```bash
forge script script/DeployPhase4.s.sol:DeployPhase4 \
  --rpc-url "$RPC_URL" \
  --account <foundry-keystore-account>

forge script script/DeployPhase4.s.sol:DeployPhase4 \
  --rpc-url "$RPC_URL" \
  --account <foundry-keystore-account> \
  --broadcast --verify
```

The broadcasting signer is the initial protocol admin. Review the treasury, staking token, stake amounts, fee basis points, timing, arbitrators, and verifier for the target network before broadcasting. Do not use the placeholder verifier for a public deployment.

Optional deployment environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TREASURY_ADDRESS` | broadcasting signer | Non-zero protocol and license treasury fallback |
| `ADMIN_ADDRESS` | broadcasting signer | Optional explicit initial admin; when set, it must equal the selected broadcast signer |
| `AXIOM_MIN_STAKE` / `AXIOM_MIN_APPEAL_STAKE` | `0.01 ether` / `0.02 ether` | Dispute and appeal stake floors |
| `AXIOM_STAKE_TOKEN` | zero address | Zero selects native ETH; non-zero must be a deployed token contract |
| `AXIOM_PROTOCOL_FEE_BPS` | `500` | Resolution fee in basis points |
| `AXIOM_RESPONSE_PERIOD` / `AXIOM_EVIDENCE_PERIOD` / `AXIOM_APPEAL_PERIOD` | `3 days` each | Periods in seconds |
| `AXIOM_ARBITRATOR` | unset | Optional deployed arbitrator to approve |
| `AXIOM_ZK_VERIFIER` | unset | Optional deployed verifier; privacy calls remain unavailable when unset |
| `AXIOM_APPROVE_ZK_VERIFIER` | `false` | Calls the production-readiness check; succeeds only for a verifier advertising the required schema and production-ready key |

The script reads numeric durations as seconds. Values are validated by the production configuration APIs, and all configured values are read back before the broadcast completes. The reserved `rewardBps` and `slashBps` fields are fixed to zero until the protocol has a fully funded counter-bond/reward model.

Existing broadcast artifacts are historical evidence, not a current release declaration. The registry's new append-only record enumeration cannot reconstruct record IDs created by an older implementation, so a fresh deployment is required when complete enumeration of all records is expected.

`DeployPhase3` is retained only as an explicitly acknowledged migration tool for an otherwise empty legacy router. It requires `AXIOM_ACK_UNSAFE_LEGACY_MIGRATION=true` and does not reconstruct old record indexes, license state, active disputes, or native-stake escrow accounting. A populated deployment needs a separately designed and audited state migration; the acknowledgement flag does not make that upgrade safe.

## ABI and CI

CI runs formatting, size-aware build, the full test suite, coverage, and canonical ABI generation. The ABI artifact is generated from `AxiomFacets`:

```bash
forge inspect AxiomFacets abi --json > axiom-router-abi.json
```

Frontend integrations should consume that generated ABI after contract CI passes instead of maintaining a hand-edited selector list.

## Security and release checklist

Before a public testnet or mainnet release:

1. Generate and independently verify the real circuit and Groth16 verification key.
2. Exercise deployment plus post-deploy assertions on a fresh network deployment.
3. Validate external arbitrator and ERC-20 stake integrations end to end.
4. Complete an independent security review and resolve its findings.
5. Publish reproducible addresses, compiler settings, ABI, and verification artifacts for the exact release commit.

## License

MIT. See `LICENSE`.
