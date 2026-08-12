# Axiom Differential Security Review — 2026-08-12

This review records the release-readiness pass over the Axiom contracts and
the companion frontend. It covers the working-tree changes after contracts
`3f46c8c` and frontend `5998c37`, before the release commits created from this
review.

## Executive Summary

| Severity | Confirmed regressions | Release risks remaining |
|---|---:|---:|
| 🔴 Critical | 0 | 0 |
| 🟠 High | 0 | 0 |
| 🟡 Medium | 0 | 3 |
| 🟢 Low | 0 | 1 |

**Overall risk:** MEDIUM for an unaudited, cryptography-dependent protocol;
LOW for the exercised local/testnet flows.

**Recommendation:** CONDITIONAL. The implementation is suitable for a fresh,
controlled Sepolia deployment with privacy disabled. It is not a mainnet
release until a real production Groth16 verifier/circuit is deployed and
independently audited.

**Key metrics**

- Contracts: 42 changed or added paths, 8 routed facets, 121 canonical routed
  functions, and native router selectors kept outside the manifest.
- Frontend: 38 changed or added paths, 12 static application routes, and a
  generated ABI checked against the same 121-function interface.
- Forge: 200 tests passed, 0 failed; four invariant properties each executed
  256 runs × 500 calls (128,000 calls) with 0 reverts.
- Coverage with the CI-compatible command: 73.20% lines and 77.61% functions.
- Frontend: lint, TypeScript, 27 Vitest tests, and production build all passed.

## What Changed

### Contract-side scope

The custom ERC-1967 proxy/router now has an explicit canonical selector
manifest. Registry, treasury, identity, DID, license, dispute, and privacy
facets share proxy storage and are wired exactly once. The manifest is defined
in `script/AxiomSelectorManifest.sol:13-173`; deployment checks the eight-facet
inventory and every installed route in `script/DeployPhase4.s.sol:191-240`.

The stateful modules were hardened around their public flows:

- registry fee accounting, batch limits, refund handling, canonical record IDs,
  and append-only record enumeration;
- admin-only treasury/configuration operations and escrow-aware withdrawals;
- DID expiry/delegate checks and signature/role consistency;
- ERC-721 license ownership, expiry, deactivation, royalties, ETH/ERC-20
  payment accounting, and fee-on-transfer rejection;
- dispute evidence, arbitration, appeal, timeout, settlement, claims, and
  assigned-arbitrator callback routing;
- privacy verifier configuration, three domain-separated public inputs,
  nullifier protection, and production-readiness checks.

`DeployPhase4` now resolves the actual Foundry broadcast signer before
initializing admin (`script/DeployPhase4.s.sol:39-48`) and refuses a conflicting
`ADMIN_ADDRESS`. It installs and verifies all canonical routes before returning.
The legacy Phase 3 script requires an explicit unsafe-migration acknowledgement.

### Frontend-side scope

The frontend consumes the generated canonical ABI and uses the same enum and
status domains as the contracts. Marketplace enumeration uses
`getRecordIds`, preserves canonical record IDs, handles every active license,
and supports ETH/ERC-20 payment paths. Registration and dispute flows use the
actual fee/stake APIs and approval semantics. Placeholder zero proofs and
privileged legacy dispute calls were removed; privacy actions fail closed until
the feature flag and a production-approved verifier are both present.

The build no longer depends on downloading Google Fonts at compile time, so CI
can build without external font-network access. Frontend CI now runs lint,
typecheck, tests, and a deterministic production build.

## Critical Findings

No confirmed Critical, High, or Medium exploitable regression remained after
the adversarial and test pass. In particular, the review did not find an
unprivileged path to drain treasury funds, bypass dispute party/role checks,
reuse a nullifier, purchase an exclusive license twice, or bypass the banned
address guard across facets.

The following are release conditions rather than confirmed vulnerabilities:

### 🟡 Production verifier is intentionally not supplied

**Files:** `src/core/AxiomPrivacyFacet.sol:374-471` and `src/core/Verifier.sol`

The facet requires a configured verifier, an exact three-input schema, and an
explicit `PRODUCTION_READY()` response before approval. The repository's
placeholder verifier is not production-ready, and the frontend disables
privacy writes by default. A real circuit, proving/verifying key ceremony,
verifier deployment, and independent cryptographic review are required before
enabling this path.

### 🟡 Fresh deployment is required for complete enumeration

The new registry enumeration index is append-only and cannot reconstruct IDs
created by the historical deployment. `DeployPhase4` is therefore the release
deployment path; old broadcast output is ignored and must not be presented as
the current release. Existing user data needs an explicit migration plan if it
must be retained.

### 🟡 Custom router semantics need external review

The system is a hybrid ERC-1967/UUPS proxy with a custom selector router, not a
full EIP-2535 Diamond. Native router selectors (`pause`, `unpause`, and
`supportsInterface`) intentionally bypass the facet manifest. This is tested
for uniqueness and collision safety, but the storage/upgrade model still
deserves an independent audit before mainnet funds or user data are exposed.

### 🟢 Dependency and operational review

OpenZeppelin, Foundry, Next.js, wagmi, and viem remain external trust and
upgrade surfaces. Pinning and CI gates are present, but dependency updates,
RPC selection, signer custody, and deployment secrets remain operational
responsibilities.

## Test Coverage Analysis

The final commands were run from the release working tree:

```text
forge fmt --check                                      PASS
forge build --skip test                                PASS
forge test                                              200 passed, 0 failed
forge coverage --ir-minimum --exclude-tests ...         73.20% lines / 77.61% funcs
npm run lint                                            PASS
npm run typecheck                                       PASS
npm test                                                27 passed, 0 failed
npm run build                                           PASS (14/14 static pages)
```

The CI coverage floor is 65% lines and 60% functions; the measured result is
above both floors. Coverage is not proof of cryptographic correctness, economic
soundness on a live chain, or third-party arbitrator behavior. Deployment
scripts and the placeholder verifier have deliberately low runtime coverage;
their safety is instead checked by manifest/deployment tests and fail-closed
configuration guards.

## Blast Radius Analysis

| Surface | Quantified reach | Primary controls |
|---|---:|---|
| Router dispatch and upgrade | 121 selectors / 8 facets | native-selector collision tests, route uniqueness, admin/UUPS guards |
| Registry and treasury | 8 + 10 selectors; all record/fee flows | fee/refund tests, escrow accounting, admin-only withdrawal |
| DID and identity | 22 + 7 selectors | expiry, delegate, signature, role, and banned-user tests |
| License/NFT economy | 28 selectors; marketplace + profile flows | ownership/approval, expiry, royalty, ETH/ERC-20 delta tests |
| Disputes | 24 selectors; initiate → evidence → arbitration → appeal/claim | party/status/deadline guards, callback mapping, invariant accounting |
| Privacy | 14 selectors; register/ownership/erasure flows | verifier approval gate, domain-separated inputs, nullifier tests |
| Frontend | 12 app routes and shared hooks | canonical ABI/domain tests, fail-closed env/chain/privacy guards |

The highest-risk state transitions are dispute settlement/claim, license
payment and transfer, treasury withdrawal, proxy routing/upgrade, and privacy
proof verification. Each has direct tests plus cross-module integration
coverage; dispute and accounting paths additionally receive invariant fuzzing.

## Historical Context

The baseline deployment scripts routed fewer selectors than the aggregate ABI,
which meant the deployed Sepolia wiring did not expose several UI and
integration entry points. The release manifest and parity tests make the
121-selector contract/interface/deployment relationship explicit.

The prior test harness targeted every deployed facet and the router rather than
only the handler, allowing invariant calls to exercise privileged entry points
and masking meaningful state exploration. `AxiomInvariant` now targets the
handler, and all four invariants execute with zero reverts.

The prior frontend contained enum/API mismatches, placeholder proofs, and
non-canonical record enumeration. These were removed or aligned rather than
silently tolerated. Legacy source functions that are not part of the reviewed
public API remain excluded from the canonical manifest and are covered by
explicit exclusion tests.

## Recommendations

### Immediate (blocking for mainnet)

- [ ] Produce and independently review the real privacy circuit, verifier,
  proving/verifying keys, and deployment ceremony; then set the production
  approval flag only for that verified address.
- [ ] Perform an independent audit of the custom router/storage/upgrade model.
- [ ] Decide the data migration plan before replacing the historical deployment
  with a fresh Phase 4 deployment.

### Before a public testnet release

- [ ] Deploy Phase 4 from the intended signer and verify the emitted route and
  configuration assertions on-chain.
- [ ] Configure and test a real arbitrator and any ERC-20 stake/license tokens
  on the target network.
- [ ] Run frontend smoke tests against the deployed address with privacy still
  disabled unless the verifier gate is complete.

### Technical debt

- [ ] Add live-chain deployment smoke tests and a documented migration tool for
  legacy record IDs.
- [ ] Revisit low-coverage deployment/placeholder-verifier code after those
  operational artifacts exist.

## Analysis Methodology

**Strategy:** FOCUSED security differential review for a medium-sized Solidity
and Next.js codebase, with deep attention to auth, value transfer, external
calls, cryptographic gates, state transitions, and cross-module flows.

**Techniques applied:** baseline/history inspection, selector and ABI parity
analysis, caller/role tracing, adversarial transaction ordering, fee-on-transfer
and escrow accounting checks, invariant fuzzing, integration tests, frontend
domain/ABI tests, lint/typecheck/build gates, and `git diff --check`.

**Scope:** all changed contract interfaces, router/storage/facets, deployment
scripts, security/integration/invariant tests, and all changed frontend hooks,
pages, components, ABI/configuration, and CI files. Generated broadcast output,
local ABI scratch output, `node_modules`, `.next`, and dotenv secrets were not
part of the release diff.

**Limitations:** external dependencies, live RPC behavior, arbitrator honesty,
gas economics under production load, and cryptographic soundness of a future
verifier were not independently audited here. Confidence is HIGH for the
tested local state-machine and accounting paths, MEDIUM for deployment and
integration behavior, and LOW for any future privacy circuit until reviewed.

## Appendix: Release Evidence

- Contracts baseline: `3f46c8c38a9f6389e272d598fc220337a2167164`.
- Frontend baseline: `5998c37d0f35aed8c4a4ecf27e2587bafd2a18a6`.
- Canonical interface count: `forge inspect AxiomFacets abi --json` → 121
  functions.
- Historical broadcast and root generated ABI are ignored by `.gitignore`; the
  checked-in source, manifest, tests, and frontend ABI generator are the source
  of truth.
