# ANTUMBRA

**La couche de confiance de l'économie humains-machines.**

ANTUMBRA est une blockchain de règlement privée par défaut, finalisée en
moins de six secondes, minable sur processeur grand public, et gouvernée
par une réputation que le capital ne peut pas acheter. Elle distingue les
humains (les **Braises**, une par personne, sans biométrie) des agents
logiciels (les **Ciphers**, parrainés, à périmètre de dépense révocable),
et rend cette confiance vérifiable par n'importe quel contrat, comptable
ou régulateur, sans jamais exposer les soldes.

Le nom vient de l'astronomie : lors d'une éclipse annulaire,
l'antéombre est la zone d'où l'on voit un anneau de lumière autour du
disque sombre. C'est l'architecture même du réseau : un noyau privé par
construction, entouré d'un anneau de vérification que chacun peut
allumer, à la demande, sans exposer personne d'autre que soi.

## Les chiffres de référence

| Grandeur | Valeur |
|---|---|
| Monnaie | ATU |
| Plafond | 16 180 339 unités (le nombre d'or × 10<sup>7</sup>) |
| Émission | 34 éclipses de 4 ans, ×0,618 par éclipse, cap exact en 136 ans |
| Blocs | toutes les 2 secondes (BlockDAG type GHOSTDAG) |
| Finalité économique | moins de 6 secondes (checkpoints de l'Anneau, 37/55) |
| Minage | RandomX, processeur seul : un ordinateur, une part |
| Confidentialité | anneau de 16, montants engagés (Pedersen), Tor par défaut |
| Divulgation | sélective à trois niveaux (Lumen) |
| Réputation | Kléos : Fait 40 + Écho 30 + Durée 30, non transférable |
| Prémine | 0 % ; trésorerie communautaire 6,18 % pendant 32 ans |

## Le livre blanc

Le document de référence complet est le
[livre blanc v1.0](docs/livre-blanc/ANTUMBRA-livre-blanc-v1.0.pdf) :
architecture, cycle de vie d'une transaction avec ses constructions
cryptographiques, algorithme de réputation et règles correctives,
économie du nombre d'or, contrats en trois étages, registre des menaces
et feuille de route de dix-huit mois.

## Ce que ce dépôt contient

```
docs/livre-blanc/   le livre blanc v1.0 (PDF, 30 pages)
spec/adr/           les décisions d'architecture (ADR 001 à 007)
simulations/        le simulateur déterministe du noyau social (Kléos)
code/               le point de départ du nœud (phase 2 de la feuille de route)
```

La simulation de `simulations/` rejoue seize ans d'histoire du réseau
avec une ferme de faux profils et une baleine au capital illimité : la
spécification v2 laissait l'attaquant capturer les 55 sièges de
l'Anneau ; les règles correctives R1 à R4 ont refermé la fenêtre, et la
même attaque ne prend plus un seul siège. La simulation est le test de
régression du noyau social : toute modification des règles doit la
faire repasser au vert.

```bash
cd simulations && python3 kleos.py
# EXIT OK : toutes les invariants tiennent.
```

## Statut et feuille de route

Le projet est en **phase 1 : spécification**. La feuille de route
complète (dix-huit mois, six phases, critère de sortie binaire à chaque
étape) est détaillée au chapitre 16 du livre blanc :

1. Spécification et ADR 001 à 007
2. Prototype BlockDAG CPU sur réseau de développement
3. Anneau et Kléos v0 (finalité sous 6 secondes)
4. Identités Braise/Cipher et clés Lumen
5. Réseau d'essai public
6. Genesis

## Méthode

Le code est écrit selon la méthode zéro-faute du livre blanc (chapitre
15) : double implémentation croisée sur vecteurs d'essai, simulation
déterministe des règles avant tout code, construction reproductible,
relecture croisée, audit externe du différenciel, critères GO/NO-GO
publics. Un NO-GO est un résultat acceptable et publié. Voir
[CONTRIBUTING.md](CONTRIBUTING.md).

Le site du projet est [xelisvault.xyz](https://xelisvault.xyz).

## Licence

Le code est publié sous licence MIT. Le livre blanc est publié sous
licence Creative Commons BY-SA 4.0. La spécification est publique,
attaquable, et sera révisée comme le code.
