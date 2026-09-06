# ADR-012: the ring signature, MLSAG over the Veil core

Status: **Proposed**

## Context

The whitepaper (Section 4, steps 3 and 4) spends an output through a
ring: sixteen candidate one-time keys, one real, fifteen decoys, and
a signature that proves knowledge of the one secret behind one of
the sixteen without saying which. The linkability requirement is
carried by the key image, already defined by ADR-011: two spends of
the same output must produce the same image and nothing else may
link them. The construction must reuse the Veil core unchanged, stay
auditable clause by clause, and never invent a primitive.

## Decision

The signature is MLSAG (linkable ring signature, the CryptoNote
lineage construction), over one ring of one-time public keys, as a
module of the `antumbra-veil` crate. The conventions, frozen here:

1. The ring. A non-empty list of strictly distinct one-time public
   keys, each decoded under the strict rules of ADR-011 (canonical,
   prime-order subgroup). The primitive accepts any size from 2 to
   1024; the version 2 transaction layer pins the protocol size of
   sixteen, fifteen decoys around the real key. Decoy selection
   policy (age brackets, spending distribution) belongs to the
   wallet, never to the consensus: the signature itself is
   independent of how the decoys were chosen.
2. The key image. I = p Hp(P_real), computed by the signer from the
   one-time secret p; the verifier checks the whole signature
   against it without recomputing it, and the nullifier registry of
   the ordering layer stores it verbatim.
3. The challenge chain. For a message m and ring members P_i:
   the signer draws a nonce alpha, publishes L = alpha G and
   R = alpha Hp(P_real), and computes
   c_{next} = Hs(tag, m, L, R) with the fixed domain tag
   "ANTUMBRA/veil/mlsag" prepended once, then walks the ring from
   the real index, each step publishing s_i uniform and computing
   L_i = s_i G + c_i P_i, R_i = s_i Hp(P_i) + c_i I, and
   c_{i+1} = Hs(tag, m, L_i, R_i). The ring closes at the real
   index with s_real = alpha - c_real p. The signature is
   (I, c_0, s_0, ..., s_{n-1}); the verifier recomputes the whole
   chain and requires the closing equality c_n = c_0.
4. The nonces. The crate is RNG-free: the signature routine derives
   every nonce from a 32-byte seed supplied by the wallet,
   alpha = Hs(seed, 0x00, index) and s_i = Hs(seed, 0x01, i), with
   the index in four little-endian bytes. The wallet must supply a
   fresh uniformly random seed per signature: reusing a seed across
   two signatures of the same secret leaks the secret exactly as a
   reused Schnorr nonce does. The derivation is deterministic so
   that the archived vectors reproduce it bit for bit.
5. The canonical encoding. image:32B, first challenge:32B, member
   count:varint, then count scalars of 32B each. Decoding is
   strict: the count must lie in [2, 1024], every scalar canonical
   (nonzero, below the group order), the image a strict ADR-011
   point, no trailing bytes. Verification requires the encoded
   member count to equal the ring size it is verified against.
6. Verification returns a boolean. A signature is valid or it is
   not: the verifier recomputes the chain, checks the closing
   equality, and nothing else (the structural rules were enforced
   at decode).

The archived vector set gains a ring section: full signatures over
rings of several sizes and real indices, reproduced bit for bit by
the independent implementation, plus a deterministically tampered
signature that must fail verification, and the linkability pair:
the same secret spent in two different rings produces the same key
image.

## Discarded options

Borromean or AOS ring signatures (no key image, no native
linkability); Monero's multi-input MLSAG chaining (a transaction
assembly concern, not a primitive concern; it will be decided when
the version 2 container is assembled); random nonces from an
in-crate RNG (an RNG dependency in consensus code, and vectors that
cannot reproduce); Schnorr over the whole ring (does not hide the
signer).

## Required validation

The ring vectors of `antumbra-veil` reproduced bit for bit by the
independent Python implementation; rejection tests on every invalid
encoding; tampering tests on message, challenge, scalars and image;
the linkability pair green; the untraceability property resting on
the CryptoNote lineage proof, with the composition left to the
external audit of phase 4.
