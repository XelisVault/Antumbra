# ANTUMBRA

**The trust layer of the human-machine economy.**

[![CI](https://github.com/XelisVault/Antumbra/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/XelisVault/Antumbra/actions/workflows/ci.yml)

ANTUMBRA is a private-by-default settlement blockchain, finalized in
under six seconds, mineable on commodity processors, and governed by a
reputation that capital cannot buy. It separates humans (the **Embers**,
one per person, no biometrics) from software agents (the **Ciphers**,
sponsored, with a revocable spending perimeter), and makes that trust
verifiable by any contract, accountant or regulator, without ever
exposing balances.

The name comes from astronomy: during an annular eclipse, the
antumbra is the zone from which one sees a ring of light around the
dark disk. That is the architecture of the network itself: a core that
is private by construction, surrounded by a ring of verification that
anyone can switch on, on demand, without exposing anyone else.

## Reference numbers

| Quantity | Value |
|---|---|
| Currency | ATU |
| Cap | 16,180,339 units (the golden ratio x 10^7) |
| Emission | 34 eclipses of 4 years, x0.618 per eclipse, exact cap at year 136 |
| Blocks | every 2 seconds (GHOSTDAG-family BlockDAG) |
| Economic finality | under 6 seconds (Ring checkpoints, 37 of 55) |
| Mining | RandomX, CPU only: one computer, one share |
| Privacy | ring of 16, committed amounts (Pedersen), Tor by default |
| Disclosure | selective, three levels (Lumen) |
| Reputation | Kleos: Deed 40 + Echo 30 + Tenure 30, non-transferable |
| Premine | 0%; community treasury 6.18% for 32 years |

## The whitepaper

The complete reference document is the
[whitepaper v1.1](docs/whitepaper/ANTUMBRA-whitepaper-v1.1.pdf):
architecture, the full life cycle of a transaction with its
cryptographic constructions, the reputation algorithm and its
corrective rules, the golden-ratio economy, three-tier contracts, the
threat register, and an eighteen-month roadmap. The LaTeX source lives
next to the PDF and is revised like code.

## What this repository contains

```
docs/whitepaper/   the whitepaper v1.1 (PDF, 20 pages) and its LaTeX source
spec/adr/          the architecture decisions (ADR 000 to 013)
simulations/       the deterministic simulator of the social core (Kleos)
code/              the Rust workspace of the node (primitives, version 1
                   transactions, the Veil cryptographic core with its
                   ring signature, and the BlockDAG ordering layer with
                   its consensus order; the remaining crates follow the
                   roadmap order)
```

The simulator in `simulations/` replays sixteen years of network
history with a farm of fake profiles and a whale of unlimited capital:
the v2 specification let the attacker capture all 55 seats of the
Ring; the corrective rules R1 to R4 closed the window, and the same
attack now takes zero seats. That simulation is the regression test of
the social core: any change to the rules must pass it green again.

```bash
cd simulations && python3 kleos.py
# EXIT OK: all invariants hold.
```

## Status and roadmap

The project is in **phase 2: the node prototype**. The full roadmap
(eighteen months, six phases, one binary exit criterion per step) is
detailed in the whitepaper:

1. Specification and ADR 000 to 007
2. CPU BlockDAG prototype on a development network
3. Ring and Kleos v0 (finality under 6 seconds)
4. Ember and Cipher identities, Lumen viewing keys
5. Public test network
6. Genesis

## Method

The code follows the zero-defect method of the whitepaper: cross
double implementation on test vectors, deterministic simulation of the
rules before any code, reproducible builds, cross review, external
audit of the differential, public GO/NO-GO criteria. A NO-GO is an
acceptable, published result. See
[CONTRIBUTING.md](CONTRIBUTING.md).

The project website is [xelisvault.xyz](https://xelisvault.xyz).

## License

The code is published under the MIT license. The whitepaper is
published under Creative Commons BY-SA 4.0. The specification is
public, attackable, and will be revised like code.
