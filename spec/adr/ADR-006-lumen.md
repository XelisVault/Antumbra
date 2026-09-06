# ADR-006 : Lumen, la divulgation sélective à trois niveaux

Statut : **Proposé**

## Contexte

La confidentialité par défaut rend le réseau illisible pour les
comptables et les autorités, à moins que la divulgation ne soit une
primitive du protocole plutôt qu'une promesse. C'est la leçon de
Zcash : la lisibilité, pas la transparence, est le critère
d'acceptation.

## Décision

Trois niveaux, tous à l'initiative du propriétaire : clé de vue par
transaction (prouver un paiement précis à son destinataire), clé
d'auditeur bornée dans le temps et le périmètre, preuve de conformité
non interactive établissant un fait (montant sous plafond, ancienneté
des fonds, couverture d'un engagement) sans rien révéler d'autre. Les
preuves de conformité de phase 4 s'appuient sur Groth16, héritage
revendiqué du projet qui a inspiré la couche d'agents.

## Validation exigée

Spécification cryptographique relue par un auditeur externe en phase 4,
et démonstrateurs de preuve vérifiés sur vecteurs d'essai publiés.
