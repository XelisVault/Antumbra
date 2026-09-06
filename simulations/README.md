# Simulations ANTUMBRA

Chaque règle sociale ou économique du protocole est simulée avant
d'être codée. Les simulations sont déterministes : graine fixe,
invariants numériques, attaques maximales rejouées. Ce sont les tests
de régression de la spécification.

## kleos.py : le noyau social

Rejoue seize ans d'histoire du réseau (32 ères, graine 1618) avec trois
populations : le réseau honnête, une ferme de vingt faux profils
parrains complices (deux parrainages par an chacun, budget de témoins
illimité), et une baleine au capital illimité mais inactive.

```bash
python3 kleos.py
# EXIT OK : toutes les invariants tiennent.
```

Sorties : `kleos-sim-report.txt` (le rapport complet) et
`antumbra-kleos-curves.png` (les trajectoires de score). Dépendance :
matplotlib, et une police couvrant le français.

Historique : la première passe, avec les règles de la spécification v2,
montrait la ferme de faux profils franchir le seuil de candidature à
l'Anneau avant le réseau honnête et capturer les 55 sièges à l'année
10. Les règles correctives R1 à R4 (seuil de candidature, poids des
témoins, responsabilité des attestations, décote de l'activité
mutualisée) ont refermé la fenêtre : la même attaque ne prend plus un
seul siège, et le Kléos médian des faux profils plafonne à 11,9 contre
76,5 pour les honnêtes. La baleine, elle, plafonne à 30 dans les deux
mondes : le capital ne multiplie rien.

Toute modification des règles du Kléos doit repasser cette simulation
au vert, attaques maximales comprises, avant d'être proposée en
décision d'architecture.

## emission.py : le calendrier des éclipses dorées

Vérifie le contrat monétaire : plafond de 16 180 339 ATU, première
éclipse de 6 180 340, deuxième de 3 819 660 (dix millions exactement
après huit ans), série géométrique de raison 1/phi, cap exact à la
trente-quatrième éclipse en l'an 136, trésorerie de 6,18 % sur les
huit premières éclipses.

```bash
python3 emission.py
# total exact = 16 180 339 == cap : True
```
