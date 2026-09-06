# -*- coding: utf-8 -*-
""" ANTUMBRA — calendrier d'émission « Éclipses dorées » (v2.1).

Conception :
  cap    = 16 180 339 ATU (φ × 10^7, inchangé)
  éclipse = 8 ères = 4 ans (le tempo de Bitcoin)
  ratio  = φ⁻¹ par éclipse — chaque éclipse émet 61,8 % de la précédente
  E0     = cap × (1 − φ⁻¹) ≈ 6 180 340 ATU sur la première éclipse

Propriétés :
  - après l'éclipse 2 (8 ans) : EXACTEMENT 10 000 000 ATU existent (61,8 % du cap)
  - 99 % minés vers l'an 40 ; cap exact à la Dernière Éclipse (~an 132-136)
  - horizon ~20× plus long que la v1 (6,5 ans) — l'ordre de grandeur de Bitcoin
"""
from math import log, floor

PHI = (1 + 5 ** 0.5) / 2
R = 1 / PHI
CAP = 16_180_339
BLOCKS_PER_4Y = 4 * 365.25 * 86400 // 2  # blocs de 2 s par éclipse

E0 = round(CAP * (1 - R))
print(f"cap = {CAP:,}  φ = {PHI:.9f}  r = φ⁻¹ = {R:.9f}")
print(f"E0 = {E0:,} ATU sur la 1re éclipse (4 ans)")
print(f"blocs par éclipse (2 s) : {BLOCKS_PER_4Y:,}")
print(f"récompense initiale : {E0*10**8/BLOCKS_PER_4Y/10**8:.6f} ATU/bloc = {E0*10**8/BLOCKS_PER_4Y:,.0f} atomic/bloc")
print()

# émissions entières par éclipse (troncature), la dernière absorbe le reste
emissions = []
n = 0
while True:
    e = floor(E0 * (R ** n) + 1e-9)
    per_block = e * 10 ** 8 / BLOCKS_PER_4Y
    emissions.append(e)
    if per_block < 1:            # moins d'une unité atomique par bloc → dernier cycle utile
        break
    if n > 100:
        break
    n += 1

# la Dernière Éclipse absorbe le solde exact
total = sum(emissions)
last = CAP - total
emissions[-1] += last  # ajuste la dernière émission pour fermer au cap exact
total = sum(emissions)

print(f"nombre d'éclipses utiles : {len(emissions)} → horizon {len(emissions)*4} ans")
print(f"total exact = {total:,} == cap {CAP:,} : {total == CAP}")
print()
print("Éclipse  Années      Émission ATU      Cumul ATU        % du cap   ATU/bloc")
cum = 0
rows = []
for i, e in enumerate(emissions):
    cum += e
    pb = e * 10 ** 8 / BLOCKS_PER_4Y
    rows.append((i + 1, (i + 1) * 4, e, cum, 100 * cum / CAP, pb))
for (i, yr, e, c, pct, pb) in rows:
    print(f"{i:>3}      {yr:>4}      {e:>12,}   {c:>12,}     {pct:>6.2f} %   {pb:>12,.2f}")

# jalons
for target in (10_000_000, CAP * 0.99, CAP * 0.999):
    c = 0
    for (i, yr, e, cum2, pct, pb) in rows:
        c += e
        if c >= target:
            print(f"\njalon {target:,.0f} ATU ({100*target/CAP:.1f} %) atteint : année {yr}")
            break

# trésorerie : 6,18 % du flux des 8 premières éclipses
treasury = round(0.0618 * sum(e for (i, *_ ) in [(r[0],) for r in rows[:8]] for e in [rows[i-1][2]]))
treasury = round(0.0618 * sum(r[2] for r in rows[:8]))
print(f"\ntrésorerie (6,18 % des 8 premières éclipses, 32 ans) ≈ {treasury:,} ATU")
