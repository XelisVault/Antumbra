# -*- coding: utf-8 -*-
"""ANTUMBRA: golden eclipse emission calendar (v2.1).

Design:
  cap     = 16,180,339 ATU (phi x 10^7, unchanged)
  eclipse = 8 eras = 4 years (Bitcoin's tempo)
  ratio   = phi^-1 per eclipse: each eclipse emits 61.8% of the previous one
  E0      = cap x (1 - phi^-1) = 6,180,340 ATU over the first eclipse

Properties:
  - after eclipse 2 (year 8): EXACTLY 10,000,000 ATU exist (61.8% of cap)
  - 99% mined around year 40; exact cap at the Last Eclipse (~year 132-136)
  - horizon ~20x longer than v1 (6.5 years), Bitcoin's order of magnitude
"""
from math import log, floor

PHI = (1 + 5 ** 0.5) / 2
R = 1 / PHI
CAP = 16_180_339
BLOCKS_PER_4Y = 4 * 365.25 * 86400 // 2  # 2 s blocks per eclipse

E0 = round(CAP * (1 - R))
print(f"cap = {CAP:,}  phi = {PHI:.9f}  r = phi^-1 = {R:.9f}")
print(f"E0 = {E0:,} ATU over the 1st eclipse (4 years)")
print(f"blocks per eclipse (2 s): {BLOCKS_PER_4Y:,}")
print(f"initial reward: {E0*10**8/BLOCKS_PER_4Y/10**8:.6f} ATU/block = "
      f"{E0*10**8/BLOCKS_PER_4Y:,.0f} atomic/block")
print()

# integer emissions per eclipse (truncation), the last absorbs the remainder
emissions = []
n = 0
while True:
    e = floor(E0 * (R ** n) + 1e-9)
    if e * 10 ** 8 / BLOCKS_PER_4Y < 1:
        emissions.append(e)
        break
    emissions.append(e)
    if n > 100:
        break
    n += 1
total = sum(emissions)
emissions[-1] += CAP - total
total = sum(emissions)

print(f"{'eclipse':>8} {'year':>6} {'emission':>12} {'cumulative':>12} "
      f"{'share':>7}")
c = 0
for i, e in enumerate(emissions):
    c += e
    print(f"{i+1:>8} {(i+1)*4:>6} {e:>12,} {c:>12,} {100.0*c/CAP:>6.2f}%")

print()
print(f"total = {total:,} (cap = {CAP:,}) -> {total == CAP}")
treasury = sum(min(e, round(e * 0.0618)) for e in emissions[:8])
print(f"community treasury (6.18% of the first 8 eclipses): ~{treasury:,} ATU")
assert total == CAP, "the ledger does not close on the cap"
print("EXACT: the ledger closes on the cap.")
