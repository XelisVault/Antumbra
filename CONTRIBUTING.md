# Contribuer à ANTUMBRA

Ce projet code une monnaie : une faute peut coûter de l'argent à des
inconnus. La barre est donc plus haute que dans un projet applicatif
ordinaire, et la méthode qui suit n'est pas négociable. Elle est
détaillée au chapitre 15 du livre blanc ; ce document en est la version
exécutable.

## Les six couches de vérification

1. **Double implémentation croisée.** Toute routine d'encodage, de
   sérialisation ou de cryptographie est portée deux fois, à partir de
   la référence (C++, Rust, spécification), et les deux
   implémentations doivent produire des résultats identiques bit à bit
   sur un jeu de vecteurs d'essai généré et archivé. Une faute de
   convention ne se trouve pas à la relecture : elle se croise.
2. **Simulation déterministe avant code.** Toute règle sociale ou
   économique (Kléos, parrainages, tirage de l'Anneau, émission) est
   d'abord simulée : graine fixe, invariants numériques, attaque
   maximale rejouée. Voir `simulations/kleos.py`, qui a révélé et corrigé
   la faille de la spécification v2.
3. **Construction reproductible et tests aléatoires.** Les exécutables
   se construisent de manière déterministe ; les états aléatoires
   massifs sont rejoués en continu sur le réseau de développement.
4. **Relecture croisée.** Chaque fusion est relue par une seconde
   personne (humaine ou assistée), avec un compte rendu archivé.
5. **Audit externe du différenciel.** Aux phases 4 et 6 de la feuille
   de route, un auditeur externe relit le différenciel complet depuis
   la phase précédente.
6. **Critères GO/NO-GO publics.** Chaque phase de la feuille de route
   a un critère de sortie mesurable ; un critère non atteint bloque la
   phase suivante et le NO-GO est publié.

## Règles d'hygiène

- Jamais de code en version candidate sur une branche de release ; le
  réseau principal ne tourne que sur des fondations stables et auditées.
- Aucune primitive cryptographique exotique non auditée : on compose
  des primitives éprouvées, on n'en invente pas.
- Chaque changement de comportement du consensus passe par une
  décision d'architecture (`spec/adr/`) avant la moindre ligne de code.
- Le format des messages de commit reste factuel : ce qui a changé,
  pourquoi, et quel test le prouve.
- Les vecteurs d'essai générés sont archivés : ils sont la mémoire des
  fautes déjà capturées.

## Signaler une faille

Une faille découverte se signale en privé via les signalements de
sécurité GitHub (Security advisories), avec un délai de divulgation
responsable de 90 jours. Les failles confirmées sont créditées dans le
registre public une fois corrigées.
