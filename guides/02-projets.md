# Mener un projet, quel qu'il soit

Valable pour tous les projets : jeu, site web, application, documents, recherche…
Si un guide `projet-<nom>.md` existe pour ton projet, lis-le **en plus** de celui-ci.

## 1. Démarrer un nouveau projet

1. Choisis un nom de dossier court (`mon-projet`) et crée-le avec son `LISEZ-MOI.md`.
2. Ajoute une ligne dans **`PROJETS.md`** à la racine (crée-le s'il n'existe pas) :

   ```
   | Dossier | Projet | Statut | Dernière mise à jour |
   |---|---|---|---|
   | mon-projet | Site vitrine pour un artisan | en cours | 2026-11-13 |
   ```
   Statuts possibles : `idée`, `en cours`, `en relecture`, `terminé`, `abandonné`.
3. Demande à Benj de valider l'objectif **avant** de produire beaucoup de contenu.

## 2. Structure minimale

```
mon-projet/
  LISEZ-MOI.md   objectif, état, à faire, comment tester, questions ouvertes
  JOURNAL.md     historique des changements, le plus récent en haut
  ...            le reste dépend du projet (src/, pages/, notes/, docs/...)
```

`LISEZ-MOI.md` doit permettre à Claude de **comprendre le projet en 2 minutes** :
objectif, livrables attendus, décisions déjà prises, ce qui marche, ce qui est
incomplet, ce qui n'a pas été testé.

## 3. Avant de passer le relais à Claude

Vérifie, puis crée la tâche :

1. Tout est **complet** : pas de `TODO` bloquant, pas de `...`, pas de fichier à moitié écrit.
2. Les dépendances et prérequis sont **listés** dans `LISEZ-MOI.md` (outils, comptes,
   éléments à créer à la main).
3. Rien de sensible : pas de secret, pas de donnée personnelle.
4. `JOURNAL.md` et `PROJETS.md` sont à jour.

Puis `creer_tache(...)` avec dans `instructions` : **la version, ce qui a changé, ce
que tu veux que Claude regarde en priorité, ce que tu n'as pas pu tester** et le
**résultat attendu** (relecture seule ? tests ? mise en ligne ?).

## 4. Ce que Claude peut faire de son côté

Relire et corriger, tester, publier ou mettre en ligne quand c'est prévu et que Benj
l'a autorisé. Il **ne publie jamais publiquement sans accord explicite de Benj**.
Dis clairement dans la tâche ce que tu attends de lui.

## 5. Quand Claude a rendu son verdict

- Lis le `resultat` (`consulter_tache`), puis les fichiers modifiés.
- **N'écrase jamais** une version corrigée par une ancienne : relis le fichier avant de le modifier.
- Note les corrections importantes dans `JOURNAL.md`, mets `PROJETS.md` à jour.

## 6. Créer le guide d'un projet (si utile)

Si un projet a des règles particulières (technologie, plateforme, structure imposée),
propose à Benj d'ajouter un guide `projet-<nom>.md` ; c'est lui (ou Claude) qui
l'ajoutera au serveur. Tu peux en rédiger le contenu dans `<projet>/notes/guide-projet.md`.
