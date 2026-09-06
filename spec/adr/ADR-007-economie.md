# ADR-007 : économie, le contrat du nombre d'or

Statut : **Proposé** (calendrier vérifié par calcul exact)

## Contexte

Le plafond, la décroissance et la durée d'émission doivent être
récitables de tête dans dix ans, et l'émission doit survivre à ses
premiers mineurs : chaque génération doit trouver une émission active.

## Décision

Plafond de 16 180 339 ATU, le nombre d'or multiplié par dix millions ;
la même proportion pilote déjà RandomX (constante 0x9E3779B9). Émission
par éclipses de quatre ans, chacune émettant la fraction 1/phi de la
précédente : 6 180 340 puis 3 819 660, dont la somme vaut exactement
dix millions après huit ans ; cap exact à la trente-quatrième éclipse,
en l'an 136. Trésorerie communautaire de 6,18 % des récompenses
pendant huit éclipses, gouvernée par les Braises, extinction
automatique ensuite. Prémine nulle. Plafond strict, avec soupape
constitutionnelle de queue activable par les trois chambres.

## Validation exigée

Le calendrier exact est un script de calcul archivé
(calendrier d'émission) ; toute modification passe par la voie
constitutionnelle et refait passer le calcul.
