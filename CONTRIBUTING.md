# Contributing to ANTUMBRA

This project codes money: one fault can cost strangers real funds.
The bar is therefore higher than in an ordinary application project,
and the method below is not negotiable. It is detailed in the
whitepaper; this document is its executable version.

## The six verification layers

1. **Cross double implementation.** Every encoding, serialization or
   cryptography routine is ported twice, from the reference (C++, Rust,
   specification), and both implementations must produce bit to bit
   identical results over a generated and archived set of test vectors.
   A convention fault is not found by re-reading: it is crossed.
2. **Deterministic simulation before code.** Every social or economic
   rule (Kleos, sponsorships, the Ring draw, emission) is simulated
   first: fixed seed, numeric invariants, maximum attack replayed. See
   `simulations/kleos.py`, which revealed and fixed the flaw of the v2
   specification.
3. **Reproducible builds and random testing.** Executables build
   deterministically; massive random states are replayed continuously
   on the development network.
4. **Cross review.** Every merge is reviewed by a second person (human
   or assisted), with an archived report.
5. **External audit of the differential.** At phases 4 and 6 of the
   roadmap, an external auditor re-reads the complete differential
   since the previous phase.
6. **Public GO/NO-GO criteria.** Every roadmap phase has one measurable
   exit criterion; an unmet criterion blocks the next phase, and the
   NO-GO is published.

## Hygiene rules

- Never release-candidate code on a release branch; the main network
  runs only on stable, audited foundations.
- No unaudited exotic cryptographic primitive: we compose proven
  primitives, we do not invent them.
- Every consensus behavior change goes through an architecture decision
  (`spec/adr/`) before a single line of code.
- Commit messages stay factual: what changed, why, and which test
  proves it.
- Generated test vectors are archived: they are the memory of faults
  already caught.

## Reporting a flaw

A discovered flaw is reported privately through GitHub security
advisories, with a 90-day responsible disclosure window. Confirmed
flaws are credited in the public register once fixed.

## The rails

Every change declares where it lands, and the declaration is checked
by machine (`ci/merge_rails.py`, CI job "Merge rails"), not by
memory:

- **Rail C — consensus.** Everything under `code/crates/`. A pull
  request that touches it carries the `rail-c` label, and whenever
  crate *sources* change, the same pull request also touches
  `spec/adr/`: no consensus behavior change without an architecture
  decision record. A rail-C merge needs the full wall below.
- **Rail B — tooling.** Scripts, simulations, CI, documentation
  tooling, the website. Never allowed to touch `code/crates/`: a
  diff declaring `rail-b` while touching the consensus surface is
  refused.
- **Rail A — bounded parameters** and **rail D — constitutional**
  are specification-level rails for the live network (see the
  whitepaper); they have no merge traffic yet, and their labels
  (`rail-a`, `rail-d`) are reserved for that day.

The routing labels exist on the repository; `ci/merge_rails.py`
fails closed on any API error.

## The CI wall

Every push and every pull request runs the full battery in
`.github/workflows/ci.yml`; branch protection requires all of it
before a merge. No exception, no bypass: a red check on `main`
blocks the phase, exactly as a NO-GO criterion would.

| Job | What it refuses |
| --- | --- |
| Format | any unformatted Rust |
| Lint | any clippy warning (`-D warnings`) |
| Tests | any test failure, including the archived cross-implementation vectors |
| MSRV (1.85) | anything the declared minimum Rust toolchain cannot build |
| Build | any unlocked or failing debug/release build |
| Documentation | any broken rustdoc link |
| Security audit | any dependency with a known CVE |
| Licenses and bans | any license or duplicate-version violation |
| Vector regeneration | any divergence between the committed vectors and the Python generators (spec = tests) |
| Social core regression | any Kleos invariant breach, any emission arithmetic error, any nondeterminism |
| Whitepaper build | a whitepaper that no longer compiles, figures whose arithmetic no longer closes |
| Repository hygiene | conflict markers, trailing whitespace, missing final newlines, invalid UTF-8, unparseable shell/Python/YAML |
| Merge rails | a consensus change without the `rail-c` label, or without an ADR in the diff |

Run the same gates locally before pushing:

```bash
bash ci/check_repo_hygiene.sh
python3 ci/merge_rails.py        # no-op outside pull requests
cargo fmt --all -- --check       # in code/
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
