# Le code du nœud ANTUMBRA

Ce répertoire accueillera l'implémentation du nœud complet, à partir de
la phase 2 de la feuille de route. Le socle est un assemblage de
fondations éprouvées : la lignée CryptoNote pour la sphère privée
(adresses à usage unique, engagements Pedersen, signatures en anneau,
Bulletproofs), la littérature GHOSTDAG pour la couche d'ordre, RandomX
pour le minage processeur. Rien d'exotique : la nouveauté du projet est
dans les règles (Kléos, Braise, Cipher, Lumen, Mandats), pas dans les
primitives.

## Structure prévue

```
code/
  node/          le nœud complet : DAG, validation, propagation, RPC
  voile/         transactions privées : anneau 16, engagements, nullifiants
  anneau/        checkpoints signés, quorum 37/55, rotation d'ères
  kleos/         score de réputation à trois couches et règles R1 à R4
  identites/     Braise (parrainage, présence) et Cipher (périmètres)
  lumen/         clés de vue bornées et preuves de conformité
  mandats/       sorties à prédicat : séquestre, versements, plafonds
```

Chaque répertoire naîtra avec son jeu de vecteurs d'essai et sa
référence de croisement, conformément à la méthode du CONTRIBUTING.md :
la double implémentation précède toujours l'assemblage.

## Point de départ de la phase 2

Le premier jalon est un réseau de développement minant un DAG
processeur à deux secondes, avec propagation en tige Dandelion++,
tenant vingt-quatre heures sans réorganisation non anticipée. Tout ce
qui précède ce jalon est de la spécification, pas du code.
