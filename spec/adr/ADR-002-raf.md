# ADR-002: finality, the Ring anchored on reputation (RAF)

Status: **Proposed**

## Context

Two-second inclusion is not enough: the payment must become
irreversible in seconds. Classical committee consensus obtains that
by locking capital, which amounts to selling finality.

## Decision

A committee of fifty-five seats, drawn each era among identities with
Kleos of at least 70 and Tenure of at least fifteen eras, signs
checkpoints every four seconds; the quorum of thirty-seven signatures
finalizes everything the checkpoint covers. A seat that signs a
competing fork is stripped: its Kleos is reset to zero. Should a third
of the seats fall silent, finality falls back on proof-of-work depth
(ten blocks, twenty seconds) and the next era removes the silent
seats. No capital is locked, no yield is paid: this is not proof of
stake.

## Required validation

Finality measured under six seconds over one hundred thousand replayed
blocks in phase 3, with injected failures and silent seats.
