#!/usr/bin/env python3
"""Regenerates the two figures of the whitepaper, in place.

Figure 1, wp-en-emission.pdf: cumulative emission toward the cap and
per-eclipse emission, from the arithmetic of simulations/emission.py.
Figure 2, wp-en-kleos.pdf: Kleos trajectories over sixteen years from
the deterministic engine of simulations/kleos.py (canonical seed 1618;
the seed sweep holds on every seed, see the report).

Bitcoin-paper style: white background, black and grey ink, serif fonts,
lines distinguished by style rather than color, vector PDF output.

Usage: python3 docs/whitepaper/src/gen_figures.py
Writes: wp-en-emission.pdf, wp-en-kleos.pdf (next to this script).
Dependencies: matplotlib (see simulations/requirements.txt).
"""

import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.font_manager as fm

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "simulations"))

for path in (
    "/usr/share/fonts/truetype/liberation/LiberationSerif-Regular.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSerif-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSerif-Italic.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
):
    if os.path.exists(path):
        fm.fontManager.addfont(path)

import matplotlib.pyplot as plt

plt.rcParams["font.family"] = "serif"
plt.rcParams["font.serif"] = ["Liberation Serif", "DejaVu Serif"]
plt.rcParams["mathtext.fontset"] = "stix"
plt.rcParams["axes.unicode_minus"] = False

INK, GREY1, GREY2, GREY3 = "#000000", "#3a3a3a", "#6e6e6e", "#9c9c9c"

# ------------------------------------------------------------------
# Figure 1: the emission calendar, from the simulation module
# ------------------------------------------------------------------

import emission as em  # noqa: E402  (module prints its own report)

emissions = em.emissions
CAP = em.CAP
years = [(i + 1) * 4 for i in range(len(emissions))]
cumulative = []
running = 0
for value in emissions:
    running += value
    cumulative.append(running)
pcts = [100.0 * value / CAP for value in cumulative]


def style_ax(ax):
    ax.grid(True, color=GREY3, lw=0.55, alpha=0.55)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color(GREY1)
    ax.tick_params(colors=GREY1, labelsize=9.5)
    for label in ax.get_xticklabels() + ax.get_yticklabels():
        label.set_color(GREY1)


fig, (ax1, ax2) = plt.subplots(
    1,
    2,
    figsize=(10.2, 4.1),
    constrained_layout=True,
    gridspec_kw={"width_ratios": [1.35, 1.0]},
)

xs = [0] + years
ys = [0] + pcts
ax1.plot(xs, ys, color=INK, lw=2.0, solid_capstyle="round")
ax1.axhline(100, color=GREY2, lw=1.0, ls=(0, (6, 3)))
ax1.axhline(61.8, color=GREY1, lw=1.1, ls=(0, (2, 2)))

for year, pct, note, dy in (
    (8, 61.8, "10,000,000 ATU (61.8%), year 8", 6),
    (40, 99.0, "99%, year 40", 5),
    (136, 100.0, "exact cap, year 136", 6),
):
    ax1.plot([year], [pct], "o", color=INK, ms=4.5, mfc="white", mew=1.3,
             zorder=5)
    ax1.annotate(
        note, (year, pct), xytext=(-4, dy), textcoords="offset points",
        fontsize=8.8, color=INK, ha="right",
    )

ax1.set_xlabel("Years after genesis", fontsize=10.5)
ax1.set_ylabel("Share of the cap issued (%)", fontsize=10.5)
ax1.set_xlim(0, 140)
ax1.set_ylim(0, 108)
ax1.set_yticks([0, 20, 40, 61.8, 80, 100])
ax1.set_yticklabels(["0", "20", "40", "61.8", "80", "100"])
style_ax(ax1)

K = 12
labels = ["%d" % (i + 1) for i in range(K)]
vals = [emissions[i] for i in range(K)]
bars = ax2.bar(labels, vals, color="#d9d9d9", edgecolor=INK, lw=0.9,
               width=0.62)
bars[0].set_facecolor("#8c8c8c")
ax2.set_yscale("log")
ax2.set_ylim(10, 2 * 10**7)
ax2.set_xlabel("Eclipse (four years each)", fontsize=10.5)
ax2.set_ylabel("ATU issued (log scale)", fontsize=10.5)
ax2.annotate("6,180,340", (0, vals[0]), xytext=(5, 5),
             textcoords="offset points", fontsize=8.6, color=INK)
ax2.annotate("3,819,660", (1, vals[1]), xytext=(5, 5),
             textcoords="offset points", fontsize=8.6, color=INK)
style_ax(ax2)

out1 = os.path.join(HERE, "wp-en-emission.pdf")
fig.savefig(out1, facecolor="white")
plt.close(fig)
print("figure 1:", out1, "| eclipses:", len(emissions),
      "| sum == cap:", sum(emissions) == CAP)

# ------------------------------------------------------------------
# Figure 2: Kleos trajectories, from the simulation module
# ------------------------------------------------------------------

import kleos as sim  # noqa: E402

_, _, hV, _, _, _, _ = sim.simulate(attack=True, fixes=False)  # v2, broken
_, _, h0, _, _, _, _ = sim.simulate(attack=False)  # honest, R1-R4
_, _, hA, _, _, _, _ = sim.simulate(attack=True, fixes=True)  # attack, R1-R4

years0 = [h["year"] for h in h0]
yearsV = [h["year"] for h in hV]
yearsA = [h["year"] for h in hA]

fig, ax = plt.subplots(figsize=(9.2, 4.6), constrained_layout=True)

ax.plot(years0, [h["hon_p50"] for h in h0], color=INK, lw=2.0,
        label="Honest network, median Kleos")
ax.plot(years0, [h["hon_p90"] for h in h0], color=INK, lw=1.4, ls="--",
        label="Honest network, 90th percentile")
ax.plot(yearsV, [h["fake_max"] for h in hV], color=GREY1, lw=1.9,
        ls=(0, (5, 2)), label="Best fake profile, v2 rules (the flaw)")
ax.plot(yearsA, [h["fake_max"] for h in hA], color=GREY2, lw=1.9, ls="-.",
        label="Best fake profile, rules R1 to R4")
ax.plot(yearsA, [h["fake_med"] for h in hA], color=GREY2, lw=1.4, ls=":",
        label="Fake profiles, median, rules R1 to R4")
ax.plot(years0, [h["whale_max"] for h in h0], color=GREY3, lw=1.6,
        ls=(0, (1, 1)), label="Whale, capital only, never a candidate")
ax.axhline(sim.SEAT_THRESHOLD, color=INK, lw=1.1, ls=(0, (6, 3)))
ax.text(0.25, sim.SEAT_THRESHOLD + 2.5,
        "candidacy threshold for the Ring (Kleos 70)",
        fontsize=9.2, color=INK)

ax.set_xlabel("Years after genesis", fontsize=10.5)
ax.set_ylabel("Kleos score (0 to 100)", fontsize=10.5)
ax.set_xlim(0, 16)
ax.set_ylim(0, 100)
style_ax(ax)
ax.legend(loc="upper left", bbox_to_anchor=(0.0, -0.16), ncol=2,
          fontsize=9.0, frameon=False)

out2 = os.path.join(HERE, "wp-en-kleos.pdf")
fig.savefig(out2, facecolor="white")
plt.close(fig)
print("figure 2:", out2, "| canonical seed:", sim.SEED,
      "| sweep seeds:", sim.SWEEP_SEEDS)
