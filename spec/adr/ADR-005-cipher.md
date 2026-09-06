# ADR-005 : Cipher, l'agent responsable par construction

Statut : **Proposé**

## Contexte

Les rails de paiement agentiques de 2026 transportent des paiements
machine-à-machine sans dire qui respond de l'agent ni jusqu'où il peut
dépenser.

## Décision

Tout agent s'enregistre avec trois attaches : un parrain humain (une
Braise, responsable et révocateur), un périmètre de dépense déclaratif
et vérifiable à chaque transaction (plafonds, destinataires, marqueurs
d'usage, fenêtre de validité), et un interrupteur de révocation à une
transaction. Le Kléos d'agent construit son actif commercial.

## Validation exigée

Prototype des périmètres en phase 4 : chaque transaction d'agent est
rejetée si elle sort du périmètre, et la révocation gèle les dépenses
dès le bloc suivant.
