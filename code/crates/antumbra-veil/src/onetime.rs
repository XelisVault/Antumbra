//! One-time destination addresses (ADR-011, whitepaper step 1).
//!
//! The sender draws an ephemeral scalar r, publishes R = rG and
//! derives P = Hs(rA) G + B, where A and B are the viewing and
//! spending public keys of the recipient. The scanner replays the
//! same derivation from the other side, Hs(aR) G + B: one routine
//! computes the shared secret, because rA on the sender side equals
//! aR on the recipient side. No address is ever reused and no
//! published key appears in any transaction.

use crate::curve::{Point, Scalar};
use crate::hash::hash_to_scalar;

/// The deterministic shared secret of a payment: Hs of the
/// compressed point `secret * public`.
///
/// The sender calls it with (r, A), the scanner with (a, R): both
/// hash the same point rA = aR, and no third party can compute it.
/// The routine takes a secret scalar: constant time end to end.
#[must_use]
pub fn shared_secret(secret: &Scalar, public: &Point) -> Scalar {
    let point = public * secret;
    hash_to_scalar(&point.encode())
}

/// The one-time destination address: `shared G + spend`.
///
/// With the shared secret of (r, A) on the sender side and (a, R) on
/// the scanner side, this is exactly P = Hs(rA) G + B of the
/// whitepaper.
#[must_use]
pub fn one_time_address(shared: &Scalar, spend_public: &Point) -> Point {
    (Point::generator() * shared) + *spend_public
}

/// The ephemeral commitment of the sender: R = rG.
#[must_use]
pub fn ephemeral(ephemeral_scalar: &Scalar) -> Point {
    Point::generator() * ephemeral_scalar
}

/// Whether a scanned candidate is owned by the scanning wallet.
///
/// The scanner knows (a, B, R, P) and recomputes the candidate from
/// its private view scalar; the comparison is constant time so that
/// a probing peer learns nothing from a negative scan.
#[must_use]
pub fn is_ours(
    view_secret: &Scalar,
    spend_public: &Point,
    candidate: &Point,
    ephemeral_public: &Point,
) -> bool {
    let shared = shared_secret(view_secret, ephemeral_public);
    one_time_address(&shared, spend_public).ct_eq(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{spend_scalar, view_scalar};

    fn recipient(seed: &[u8; 32]) -> (Scalar, Scalar, Point, Point) {
        let a = view_scalar(seed);
        let b = spend_scalar(seed);
        let a_public = &Point::generator() * &a;
        let b_public = &Point::generator() * &b;
        (a, b, a_public, b_public)
    }

    #[test]
    fn sender_and_scanner_derive_the_same_address() {
        let seed = [41u8; 32];
        let (a, _b, a_public, b_public) = recipient(&seed);

        // The sender side.
        let mut r_bytes = [0u8; 32];
        r_bytes[0] = 0x09;
        let r = Scalar::decode(&r_bytes).expect("canonical");
        let r_public = ephemeral(&r);
        let shared_sender = shared_secret(&r, &a_public);
        let p_sender = one_time_address(&shared_sender, &b_public);

        // The scanner side: same shared secret, same address.
        let shared_scanner = shared_secret(&a, &r_public);
        assert!(shared_sender.ct_eq(&shared_scanner));
        assert!(is_ours(&a, &b_public, &p_sender, &r_public));

        // The published address never appears in the one-time form.
        assert!(!p_sender.ct_eq(&b_public));
    }

    #[test]
    fn a_wrong_view_secret_does_not_recognize_the_output() {
        let seed = [42u8; 32];
        let (_a, _b, a_public, b_public) = recipient(&seed);
        let mut r_bytes = [0u8; 32];
        r_bytes[1] = 0x05;
        let r = Scalar::decode(&r_bytes).expect("canonical");
        let r_public = ephemeral(&r);
        let p = one_time_address(&shared_secret(&r, &a_public), &b_public);

        // A different wallet scans: the candidate never matches.
        let other_seed = [43u8; 32];
        let (other_a, _other_b, _other_a_public, other_b_public) = recipient(&other_seed);
        assert!(!is_ours(&other_a, &other_b_public, &p, &r_public));
        // A spend key mismatch is also caught: scanning with the
        // right view secret but the wrong spend key fails.
        assert!(!is_ours(&_a, &other_b_public, &p, &r_public));
    }

    #[test]
    fn two_ephemerals_for_the_same_recipient_differ() {
        let seed = [44u8; 32];
        let (_a, _b, a_public, b_public) = recipient(&seed);
        let mut r1 = [0u8; 32];
        r1[0] = 3;
        let mut r2 = [0u8; 32];
        r2[0] = 4;
        let s1 = Scalar::decode(&r1).expect("canonical");
        let s2 = Scalar::decode(&r2).expect("canonical");
        let p1 = one_time_address(&shared_secret(&s1, &a_public), &b_public);
        let p2 = one_time_address(&shared_secret(&s2, &a_public), &b_public);
        assert!(!p1.ct_eq(&p2));
    }
}
