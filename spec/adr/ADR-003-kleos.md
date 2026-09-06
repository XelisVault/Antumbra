# ADR-003 : Kléos, la réputation à trois couches

Statut : **Proposé** (validé par simulation)

## Contexte

La réputation doit être assez solide pour porter la finalité, et assez
sobre pour ne pas devenir une monnaie. Le projet qui a inspiré cette
partie indexait la réputation sur le capital : la formule multipliait
les deux, et le riche restait au pouvoir.

## Décision

Score de 0 à 100, consensuel, non transférable : le Fait (comportement
observé, plafond 40), l'Écho (attestations des pairs, plafond 30, budget
de 0,1 par témoin et par ère), la Durée (ancienneté continue, plafond
30). Décroissances naturelles ; triche : remise à zéro du Fait ; incident
majeur : effondrement de la Durée. Quatre règles correctives issues de
la simulation : R1 seuil de candidature à 70 et quinze ères, R2 témoin
muet sous vingt points de Fait, R3 attestations responsables, R4 activité
mutualisée d'une clique comptée au quart.

## Validation exigée

La simulation déterministe (graine 1618) est le test de régression :
toute modification des règles doit la repasser au vert, attaques
maximales comprises.
