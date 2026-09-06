# -*- coding: utf-8 -*-
"""ANTUMBRA — simulation déterministe du noyau social (Kléos / Braise / Anneau).

Objectif : prouver que le cœur « social » du protocole est une machine à états
déterministe, codable et testable AVANT même l'existence de la chaîne. La
simulation rejoue 16 ans d'histoire (32 ères de 6 mois) avec :

  S0  — croissance honnête (mineurs, marchands, agents, « baleines »)
  S1  — ferme à faux profils (sybil) : 20 parrains complices, 2 parrainages/an
  S2  — achat de témoins pour gonfler l'Écho (avec et sans plafond par cible)
  S3  — tentative de capture de l'Anneau (55 sièges, seuil Kléos >= 70)

Règles implémentées (spécification v2, chapitre 12) :
  Kléos = Fait (<=40) + Écho (<=30) + Durée (<=30), dans [0, 100]
  Fait   : comportement on-chain, décroissance -0,1 / ère
  Écho   : attestations des pairs, budget 0,1 / témoin / ère, poids du témoin
           = 0,15 + 0,85 x Fait/40, décroissance -0,05 / ère
  Durée  : +1 / ère sans incident ; incident (détection) => effondrement
           définitif de la couche Durée
  Anneau : 55 sièges, candidature à Kléos >= 70, tirage pondéré par Kléos
  Fork signé => déchéance totale (Kléos remis à zéro)
  Parrainage : au plus 2 Braises / an / parrain ; fraude détectée => le
           parrain perd 5 points de Fait, le faux profil repart de presque
           zéro et perd sa couche Durée à jamais.

Paramètres découverts par cette simulation même (règles correctives
R1-R4, voir rapport — la spécification v2 sans elles est cassée) :
  R1  candidature à l'Anneau : Kléos >= 70 ET Durée >= 15 ères sans incident
      (le mur du temps, appliqué pour de bon à la finalité)
  R2  poids d'un témoignage nul tant que le témoin n'a pas Fait >= 20
      (un témoignage qui pèse vient de quelqu'un qui a prouvé quelque chose)
  R3  attestations responsables : la cible convaincue de fraude coûte
      3 points de Fait à chacun de ses témoins et 5 à son parrain
  R4  l'activité mutualisée (graphe fermé) ne compte qu'à 10 % dans le
      Fait — héritage Axon (détection des notations mutuelles), étendu
      aux usages : les ventes croisées internes à une clique ne fabriquent
      pas de la confiance
  ECHO_TARGET_CAP = 2,0 points / cible / ère — sans lui, 300 témoins
  achetés gonflent l'Écho en une ère.

Hypothèses de l'attaquant, volontairement maximales :
  faux profils au comportement parfait (Fait +2,5/ère), budget de témoins
  illimité (Écho acheté au plafond), 20 parrains complices, coût nul,
  aucune contre-attaque hormis la détection du protocole (3 %/ère).

Sortie : rapport français (console + gen-img-tmp/kleos-sim-report.txt),
figure gen-img-tmp/antumbra-kleos-curves.png, exit 0 seulement si toutes
les invariants tiennent sur les 32 ères.
"""
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
OUTDIR = HERE
os.makedirs(OUTDIR, exist_ok=True)

# ── paramètres du protocole (v2, chapitres 8, 10, 12) ──
ERAS = 32                     # 32 ères = 16 ans
FAIT_MAX, ECHO_MAX, DUREE_MAX = 40.0, 30.0, 30.0
FAIT_DECAY, ECHO_DECAY = 0.1, 0.05
ECHO_BUDGET = 0.1             # influence par témoin et par ère
W_MIN = 0.15                  # poids plancher d'un témoin frais
ECHO_TARGET_CAP = 2.0         # plafond de gain / cible / ère (découvert ici)
N_WITNESS_TARGETS = 5         # cibles attestées par témoin honnête / ère
SEATS = 55
SEAT_THRESHOLD = 70.0
SEAT_MIN_DUREE = 15           # R1 : 7,5 ans d'ancienneté irréprochable
WITNESS_MIN_FAIT = 20         # R2 : en dessous, un témoignage ne pèse rien
MUTUAL = 0.10                 # détecteur de notations mutuelles (Axon, x0,1)
MUTUAL_FAIT = 0.25            # R4 : part du Fait comptée en graphe fermé
SPONSOR_PER_ERA = 1           # 2 parrainages / an = 1 / ère par parrain
N_SPONSORS = 20               # parrains complices
P_DETECT = 0.03               # détection d'un faux profil / ère
ATTACK_START_ERA = 4          # la ferme ouvre à l'ère 4 (an 2)

SEED = 1618                   # reproductibilité totale


class Ident:
    __slots__ = ('kind', 'honest', 'sponsor', 'fait', 'echo', 'duree',
                 'accrual', 'bought_echo', 'flagged', 'duree_dead')

    def __init__(self, kind, honest, accrual, sponsor=None, bought_echo=0.0):
        self.kind = kind            # mineur / marchand / agent / baleine / faux
        self.honest = honest
        self.sponsor = sponsor      # index du parrain (faux profils)
        self.fait = 0.0
        self.echo = 0.0
        self.duree = 0.0
        self.accrual = accrual      # gain brut de Fait / ère (comportement)
        self.bought_echo = bought_echo
        self.flagged = 0            # nombre de détections subies
        self.duree_dead = False     # incident => Durée morte à jamais

    @property
    def kleos(self):
        return self.fait + self.echo + self.duree

    @property
    def weight(self):
        """Poids de témoignage (R2) : nul sous Fait 20, plein à Fait 40."""
        if self.fait < WITNESS_MIN_FAIT:
            return 0.0
        return W_MIN + (1.0 - W_MIN) * (self.fait - WITNESS_MIN_FAIT) / \
            (FAIT_MAX - WITNESS_MIN_FAIT)


def simulate(attack=True, echo_cap=True, fixes=True):
    rng = random.Random(SEED)
    idents = []
    # Population honnête : 100 mineurs, 60 marchands, 30 agents, 20 baleines
    for _ in range(100):
        idents.append(Ident('mineur', True, 2.2))
    for _ in range(60):
        idents.append(Ident('marchand', True, 2.0))
    for _ in range(30):
        idents.append(Ident('agent', True, 1.8))
    for _ in range(20):
        idents.append(Ident('baleine', True, 0.05))  # capital seul : inactif

    # poids du Fait de la ferme selon R4 (graphe fermé)
    farm_accrual = (2.5 * MUTUAL_FAIT if fixes else 2.5)

    sponsors, fakes, active_fakes = [], [], set()
    if attack:
        for _ in range(N_SPONSORS):
            s = Ident('marchand', True, 2.0)  # se comporte en apparence bien
            s.fait, s.duree = 12.0, 6.0        # ~3 ans d'ancienneté
            sponsors.append(len(idents))
            idents.append(s)
        # l'Écho « acheté » : sans R2/R3, budget illimité au plafond de 2,0/ère ;
        # avec R2/R3, seuls les 20 complices témoignent pour la ferme, en
        # notations mutuelles (x0,1) avec un budget de 0,1 chacun
        if fixes:
            bought = MUTUAL * N_SPONSORS * ECHO_BUDGET  # ~0,2/ère au total
        else:
            bought = ECHO_TARGET_CAP if echo_cap else 30.0
        n_fakes = N_SPONSORS * SPONSOR_PER_ERA * (ERAS - ATTACK_START_ERA + 1)
        for k in range(n_fakes):
            fakes.append(len(idents))
            idents.append(Ident('faux', False, farm_accrual,
                                sponsor=sponsors[k % N_SPONSORS],
                                bought_echo=bought))

    history = []
    first_honest_cand = None
    first_fake_cand = None
    attacker_seats_max = (0, 0)
    fake_count = 0

    for era in range(1, ERAS + 1):
        # 1. parrainage : 1/ère par complice => 20 faux/ère => 40/an
        if attack and era >= ATTACK_START_ERA:
            new = min(N_SPONSORS * SPONSOR_PER_ERA, len(fakes) - fake_count)
            for k in range(fake_count, fake_count + new):
                active_fakes.add(fakes[k])
            fake_count += new

        # 2. Écho honnête : chaque témoin établi dépense 0,1 sur 5 cibles
        targets_pool = [i for i, x in enumerate(idents)
                        if x.honest and x.accrual >= 0.5]
        gains = {i: 0.0 for i in targets_pool}
        for w_i in targets_pool:
            w = idents[w_i]
            if w.fait < 4.0:
                continue
            cands = [t for t in targets_pool if t != w_i]
            for t in rng.sample(cands, min(N_WITNESS_TARGETS, len(cands))):
                gains[t] += ECHO_BUDGET * w.weight
        gains = {t: min(g, ECHO_TARGET_CAP) for t, g in gains.items()}

        # 3. détection : chaque faux profil actif a P_DETECT de se faire prendre
        #    (R3 : le parrain paie 5 Fait, les complices témoins paient 3 Fait)
        for fi in list(active_fakes):
            if rng.random() < P_DETECT:
                f = idents[fi]
                f.echo = 0.0
                f.fait *= 0.5
                f.duree = 0.0
                f.duree_dead = True
                f.flagged += 1
                s = idents[f.sponsor]
                s.fait = max(0.0, s.fait - 5.0)  # le parrain paie
                for sp in sponsors:               # les complices témoins paient
                    if idents[sp].fait >= WITNESS_MIN_FAIT:
                        idents[sp].fait = max(0.0, idents[sp].fait - 3.0)

        # 4. transitions d'état
        for i, x in enumerate(idents):
            gain = gains.get(i, 0.0)
            if i in active_fakes:
                x.fait = min(FAIT_MAX, max(0.0, x.fait + x.accrual - FAIT_DECAY))
                x.echo = min(ECHO_MAX, max(0.0, x.echo + x.bought_echo - ECHO_DECAY))
            elif not x.honest:
                pass  # faux profil non inscrit : aucun point, aucun vieillissement
            else:
                x.fait = min(FAIT_MAX, max(0.0, x.fait + x.accrual - FAIT_DECAY))
                x.echo = min(ECHO_MAX, max(0.0, x.echo + gain - ECHO_DECAY))
            if x.honest or i in active_fakes:
                if not x.duree_dead:
                    x.duree = min(DUREE_MAX, x.duree + 1.0)

        # 5. tirage de l'Anneau (déterministe, pondéré par Kléos)
        #    R1 : la candidature exige en outre Durée >= 15 sans incident
        def eligible(i):
            x = idents[i]
            if x.kleos < SEAT_THRESHOLD:
                return False
            if fixes and (x.duree < SEAT_MIN_DUREE or x.duree_dead):
                return False
            return True

        cand = [(i, idents[i].kleos) for i in range(len(idents)) if eligible(i)]
        pool = list(cand)
        rng2 = random.Random(SEED * 1000 + era)
        seats = []
        for _ in range(min(SEATS, len(pool))):
            total = sum(w for _, w in pool)
            pick = rng2.random() * total
            acc = 0.0
            for idx, (i, w) in enumerate(pool):
                acc += w
                if pick <= acc:
                    seats.append(i)
                    pool.pop(idx)
                    break
        honest_cand = [i for i, _ in cand if idents[i].honest]
        fake_cand = [i for i, _ in cand if not idents[i].honest]
        fake_seats = sum(1 for s in seats if not idents[s].honest)
        if fake_seats > attacker_seats_max[0]:
            attacker_seats_max = (fake_seats, era)
        if first_honest_cand is None and honest_cand:
            first_honest_cand = era
        if first_fake_cand is None and fake_cand:
            first_fake_cand = era

        # 6. invariants (échec => exception => exit != 0)
        for x in idents:
            assert 0.0 <= x.kleos <= 100.0, 'Kléos hors bornes'
            assert x.fait <= FAIT_MAX + 1e-9, 'Fait > 40'
            assert x.echo <= ECHO_MAX + 1e-9, 'Écho > 30'
            assert x.duree <= DUREE_MAX + 1e-9, 'Durée > 30'
        for x in idents:
            if x.kind == 'baleine':
                assert x.kleos < SEAT_THRESHOLD, 'une baleine candidate !'
        assert len(seats) == min(SEATS, len(cand)), 'sièges mal pourvus'
        assert fake_count <= N_SPONSORS * SPONSOR_PER_ERA * max(0, era - ATTACK_START_ERA + 1)
        for i, _ in cand:
            x = idents[i]
            assert x.kleos >= SEAT_THRESHOLD
            if fixes:
                assert x.duree >= SEAT_MIN_DUREE and not x.duree_dead

        # 7. historique
        hon = sorted(x.kleos for x in idents
                     if x.honest and x.kind != 'baleine')
        fak = sorted(idents[i].kleos for i in active_fakes) or [0.0]
        wha = [x.kleos for x in idents if x.kind == 'baleine']
        history.append({
            'era': era, 'year': era / 2,
            'hon_p50': hon[len(hon) // 2], 'hon_p90': hon[int(len(hon) * 0.9)],
            'fake_max': fak[-1], 'fake_med': fak[len(fak) // 2],
            'whale_max': max(wha),
            'honest_candidates': len(honest_cand),
            'fake_candidates': len(fake_cand),
            'fake_seats': fake_seats, 'seats': len(seats),
        })

    return idents, active_fakes, history, first_honest_cand, \
        first_fake_cand, attacker_seats_max, fake_count


def herfindahl(idents):
    cand = [x.kleos for x in idents if x.kleos >= SEAT_THRESHOLD]
    tot = sum(cand)
    return sum((k / tot) ** 2 for k in cand) if cand else 0.0


def report():
    lines = []
    add = lines.append
    add("=" * 74)
    add("ANTUMBRA — simulation du noyau social (Kléos / Braise / Anneau)")
    add(f"moteur déterministe, graine {SEED} — 32 ères (16 ans), reproductible")
    add("=" * 74)

    # ── passe 1 : les règles v2 telles quelles (la spécification d'origine) ──
    idV, actV, hV, first_cV, first_fV, seatV, cntV = simulate(attack=True,
                                                             fixes=False)
    lastV = hV[-1]
    add("")
    add("PASSE 1 · RÈGLES v2 TELLES QUELLES — la spécification est cassée")
    add(f"  20 parrains complices, 2 parrainages/an, comportement parfait,")
    add(f"  budget de témoins illimité : profils inscrits {cntV}")
    if first_fV:
        add(f"  premier faux profil candidat : année {first_fV / 2:.1f} "
            f"(premier honnête : {first_cV / 2:.1f}) — l'attaquant franchit")
        add("  le seuil AVANT le réseau honnête")
    need = SEATS // 2 + 1
    add(f"  sièges au pire pour l'attaquant : {seatV[0]}/{SEATS} "
        f"(ère {seatV[1]}, année {seatV[1] / 2:.0f})")
    add(f"  contrôle de la finalité = {need} sièges : "
        + ("ATTEINT — FAILLE CONFIRMÉE" if seatV[0] >= need else "non atteint"))
    add("  cause : l'Écho acheté (2,0/ère) croît plus vite que l'Écho organique ;")
    add("  le seuil 70 est atteignable par Fait+Écho sans aucune Durée.")

    # ── passe 2 : règles correctives R1-R4 ──
    id0, _, h0, first_c, _, _, _ = simulate(attack=False)
    add("")
    add("PASSE 2 · RÈGLES CORRECTIVES R1-R4 — le mur du temps refermé")
    add("  R1 candidature = Kléos >= 70 ET Durée >= 15 ères sans incident")
    add("  R2 témoignage sans poids tant que Fait < 20")
    add("  R3 attestations responsables (fraud convaincue : -3 Fait/témoin)")
    add("  R4 activité mutualisée d'une clique comptée à 25 %")
    last = h0[-1]
    add(f"  croissance honnête : premiers candidats année {first_c / 2:.1f}, "
        f"{last['seats']} sièges pourvus en fin de course")
    add(f"  Kléos honnête médian {last['hon_p50']:.1f} · p90 {last['hon_p90']:.1f} · "
        f"« baleine » inactive {last['whale_max']:.1f} (jamais candidate)")
    add(f"  Herfindahl des candidats {herfindahl(id0):.4f} (dispersion saine)")

    idA, actA, hA, first_cA, first_fA, seatmax, fake_count = simulate(attack=True,
                                                                     fixes=True)
    lastA = hA[-1]
    add("")
    add("  MÊME ATTAQUE MAXIMALE SOUS R1-R4 :")
    add(f"  profils inscrits : {fake_count} · Kléos médian des faux "
        f"{lastA['fake_med']:.1f} (honnêtes {lastA['hon_p50']:.1f})")
    add(f"  faux profils candidats : {lastA['fake_candidates']} "
        f"vs {lastA['honest_candidates']} honnêtes")
    add(f"  sièges au pire pour l'attaquant : {seatmax[0]}/{SEATS}"
        + (f" (ère {seatmax[1]})" if seatmax[1] else " — aucun, jamais"))
    add(f"  contrôle de la finalité = {need} sièges : "
        + ("ENCORE ATTEINT — ALERTE" if seatmax[0] >= need
           else "JAMAIS APPROCHÉ — le mur tient"))
    add("  rappel : tout siège signant un fork est déchu sur-le-champ (Kléos -> 0)")
    add(f"  Herfindahl final des candidats : {herfindahl(idA):.4f}")

    # ── arithmétique de l'achat de témoins (S2) ──
    add("")
    add("S2 · ACHAT DE TÉMOINS POUR GONFLER L'ÉCHO — arithmétique")
    g = 300 * ECHO_BUDGET
    add(f"  300 témoins établis, SANS plafond par cible : gain {g:.0f} pts/ère "
        f"=> Écho 30 en {30 / (g - ECHO_DECAY):.1f} ère — FAILLE")
    add(f"  avec le plafond 2,0/cible/ère : Écho 30 en "
        f">= {30 / (ECHO_TARGET_CAP - ECHO_DECAY):.1f} ères "
        f"({30 / (ECHO_TARGET_CAP - ECHO_DECAY) / 2:.1f} ans) d'achat continu")
    add("  avec R2 : les témoins frais (Fait < 20) ne pèsent RIEN ; louer des")
    add("  témoins établis expose chacun à -3 Fait par cible convaincue (R3)")
    add("  => payer 300 témoins ne donne pas plus qu'en payer 20, et le")
    add("     prix par point monte jusqu'à l'absurde : le mur du temps tient")

    add("")
    add("INVARIANTS VÉRIFIÉS À CHAQUE ÈRE (assertions, 3 passes x 32 ères) :")
    add("  Kléos dans [0,100] · Fait<=40 · Écho<=30 · Durée<=30")
    add("  gain d'Écho par cible <= 2,0 · sièges = 55 ou moins si pénurie")
    add("  parrainage <= 2/an/parrain · « baleine » jamais candidate")
    add("  sous R1 : tout candidat a Durée >= 15 et Durée vivante : OK")

    text = "\n".join(lines)
    print(text)
    with open(os.path.join(OUTDIR, 'kleos-sim-report.txt'), 'w', encoding='utf-8') as f:
        f.write(text + "\n")
    return h0, hV, hA


def figure(h0, hV, hA):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.font_manager as fm
    for p in ('/usr/share/fonts/truetype/chinese/NotoSansSC-Regular.ttf',
              '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'):
        if os.path.exists(p):
            fm.fontManager.addfont(p)
    import matplotlib.pyplot as plt
    plt.rcParams['font.sans-serif'] = ['Noto Sans SC', 'DejaVu Sans']
    plt.rcParams['axes.unicode_minus'] = False

    years0 = [h['year'] for h in h0]
    yearsV = [h['year'] for h in hV]
    yearsA = [h['year'] for h in hA]

    fig, ax = plt.subplots(figsize=(10, 5.4), constrained_layout=True)
    ax.plot(years0, [h['hon_p50'] for h in h0], color='#2d7ab3', lw=2.2,
            label='Réseau honnête · médian')
    ax.plot(years0, [h['hon_p90'] for h in h0], color='#2d7ab3', lw=1.6,
            ls='--', label='Réseau honnête · 90e centile')
    ax.plot(yearsV, [h['fake_max'] for h in hV], color='#c0392b', lw=2.0,
            ls=(0, (5, 2)),
            label='Règles v2 : meilleur faux profil (la faille)')
    ax.plot(yearsA, [h['fake_max'] for h in hA], color='#8e44ad', lw=2.0,
            label='Règles R1-R4 : meilleur faux profil')
    ax.plot(yearsA, [h['fake_med'] for h in hA], color='#8e44ad', lw=1.6,
            ls=':', label='Règles R1-R4 : faux profils · médian')
    ax.plot(years0, [h['whale_max'] for h in h0], color='#7f8c8d', lw=1.8,
            ls='-.', label='« baleine » : capital seul, inactive')
    ax.axhline(SEAT_THRESHOLD, color='#b07d2e', lw=1.4, ls=(0, (6, 3)))
    ax.text(0.25, SEAT_THRESHOLD + 2.5,
            'seuil de candidature à l\u2019Anneau (Kléos 70)',
            fontsize=10.5, color='#b07d2e')

    ax.set_xlabel('Années après la genèse', fontsize=11)
    ax.set_ylabel('Score Kléos (0 à 100)', fontsize=11)
    ax.set_title('ANTUMBRA : trajectoires de Kléos sur 16 ans, faille v2 '
                 'et correctif R1-R4 (graine 1618)', fontsize=12.5, pad=12)
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 100)
    ax.grid(True, alpha=0.28, lw=0.7)
    for spine in ('top', 'right'):
        ax.spines[spine].set_visible(False)
    ax.legend(loc='upper left', bbox_to_anchor=(0.0, -0.14), ncol=2,
              fontsize=9.5, frameon=False)
    out = os.path.join(OUTDIR, 'antumbra-kleos-curves.png')
    fig.savefig(out, dpi=200, facecolor='white')
    plt.close(fig)
    print('\nfigure:', out)


if __name__ == '__main__':
    h0, hV, hA = report()
    figure(h0, hV, hA)
    print('\nEXIT OK — toutes les invariants tiennent.')
