# ADR-006: Lumen, selective disclosure on three levels

Status: **Proposed**

## Context

Privacy by default makes the network unreadable for accountants and
authorities unless disclosure is a protocol primitive rather than a
promise. That is the lesson of Zcash: readability, not transparency,
is the acceptance criterion.

## Decision

Three levels, all initiated by the owner: a per-transaction viewing
key (proving one precise payment to its recipient), an auditor key
bounded in time and scope, and a non-interactive compliance proof
establishing a fact (amount under a ceiling, age of funds, coverage of
an engagement) without revealing anything else. The phase 4 compliance
proofs build on Groth16, the claimed heritage of the project that
inspired the agent layer.

## Required validation

Cryptographic specification reviewed by an external auditor in phase
4, and proof demonstrators verified on published test vectors.
