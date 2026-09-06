# ADR-002 : finalité, l'Anneau ancré sur la réputation (RAF)

Statut : **Proposé**

## Contexte

L'inclusion en deux secondes ne suffit pas : le paiement doit devenir
irréversible en secondes. Les consensus à comité classiques l'obtiennent
en verrouillant du capital, ce qui revient à vendre la finalité.

## Décision

Un comité de cinquante-cinq sièges, tirés à chaque ère parmi les
identités à Kléos d'au moins 70 et à la Durée d'au moins quinze ères,
signe des points de contrôle toutes les quatre secondes ; le quorum de
trente-sept signatures finalise tout ce que le point de contrôle couvre.
Un siège qui signe un fork concurrent est déchu : son Kléos est remis à
zéro. En cas de silence du tiers des sièges, la finalité retombe sur la
profondeur de preuve de travail (dix blocs, vingt secondes) et l'ère
suivante retire les silencieux. Aucun capital n'est verrouillé, aucun
rendement n'est servi : ce n'est pas une preuve d'enjeu.

## Validation exigée

Finalité mesurée sous six secondes sur cent mille blocs rejoués en
phase 3, avec injection de pannes et de sièges silencieux.
