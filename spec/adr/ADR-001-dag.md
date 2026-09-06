# ADR-001 : couche d'ordre, un BlockDAG à convergence rapide

Statut : **Proposé**

## Contexte

La cadence visée est de deux secondes par bloc. Une chaîne linéaire à
preuve de travail perdrait à cette cadence une part insoutenable de ses
blocs en orphelins ; la confidentialité par anneau exige par ailleurs
que les sorties non dépensées soient nombreuses et bien distribuées.

## Décision

La couche d'ordre est un DAG de blocs à convergence rapide, de famille
GHOSTDAG : les blocs parallèles sont ordonnés par règle de consensus au
lieu d'être rejetés, et la sécurité cumulée croît avec le volume total
de blocs. L'élagage conserve l'état récent et les preuves du passé pour
qu'un nœud complet tienne sur un ordinateur personnel.

## Options écartées

Chaîne linéaire à blocs courts (taux d'orphelins rédhibitoire) ;
chaîne à cadence longue (confirmation trop lente pour le comptoir) ;
consensus à comité pour la production de blocs (verrou de capital,
contraire au principe égalitariste).

## Validation exigée

Prototype isolé minant un DAG processeur à deux secondes, puis
vingt-quatre heures de réseau de développement sans réorganisation
non anticipée (phase 2 de la feuille de route).
