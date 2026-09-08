# ADR-023: the honest language register

Status: **Accepted** (v1.3, editorially binding)

## Context

The second review listed the sentences that sell more than the
design delivers: "first blockchain that deploys its own
improvements", "external audit", "without a single fault". A
project that lies in its marketing has already failed its own
zero-defect method.

## Decision

The whitepaper, the README and every document of the repo obey
a closed register. Banned: "perfect", "faultless", "first
blockchain that X", "external audit" (the v1.1 review was a
public independent review, and the word "audit" is reserved
for paid, named, scoped engagements). Required: MTTD, MTTC,
MTTR as the form of every resistance claim; "independent
review" for the reviews that happened; NO-GO published with
numbers for every unmet criterion; "relatively very
resistant" as the strongest sentence about security.

## Required validation

The register is enforced the only way language can be: by
review. The v1.3 diff itself is the precedent: the Corona
slogan is withdrawn in the section that replaces it, and the
grep of the repository must return zero banned sentences
(ci/check_repo_hygiene.sh keeps a watch list).
