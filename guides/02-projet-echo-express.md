# Projet « Écho Express » (jeu Roblox)

## Le circuit de travail

Benj veut que vous construisiez ensemble un jeu Roblox, en deux temps :

1. **France Student IA (toi)** : tu développes le jeu — idée, code (Luau), première
   relecture et tests quand c'est possible — et tu déposes tout dans le dossier
   `echo-express/`.
2. **Claude** : il récupère ton code, le **relit**, le **teste dans Roblox Studio**
   et, si tout fonctionne, le **publie** sur Roblox.

Benj a choisi le concept **« Écho Express »** parmi trois idées que tu avais proposées.
Il pilote la conversation avec toi ; Claude intervient au moment de la relecture.

## Ce qui est décidé

- Publication : d'abord en **nouvelle expérience privée**. Aucune publication
  publique sans accord explicite de Benj.
- C'est Claude qui publie, pas toi : ne cherche pas à le faire.

## Structure attendue du dossier

```
echo-express/
  LISEZ-MOI.md          concept, règles du jeu, état d'avancement, à tester
  JOURNAL.md            ce qui a changé, du plus récent au plus ancien
  src/
    ServerScriptService/    scripts serveur   (un fichier .server.lua par script)
    StarterPlayerScripts/   scripts client    (un fichier .client.lua par script)
    ReplicatedStorage/      modules partagés  (un fichier .lua par module)
  notes/
    idees.md            idées écartées ou à garder pour plus tard
```

Le nom de chaque fichier de `src/` doit indiquer **où le script se place dans
Roblox Studio** (le dossier parent donne le service). Claude s'en sert pour
reconstruire le jeu.

## Ce que doit contenir `LISEZ-MOI.md`

- **Concept** en 3 à 5 phrases : but du joueur, boucle de jeu, ce qui rend le jeu original.
- **Contrôles** et **règles** de base.
- **Liste des scripts** : nom, rôle, où le placer dans Studio.
- **Objets à créer à la main dans Studio** (zones, pièces, interface) que le code suppose
  exister, avec leur nom exact. C'est la cause n°1 de bugs : décris-les précisément.
- **État** : ce qui marche, ce qui est incomplet, ce qui n'a **pas été testé**.
- **Questions ouvertes** pour Claude ou Benj.

## Avant de passer le relais à Claude

Vérifie dans cet ordre, puis crée la tâche de relecture :

1. Chaque script est **complet** (aucun `-- TODO` bloquant, aucun `...`).
2. Les noms d'objets utilisés dans le code (`workspace.XXX`, `ReplicatedStorage.XXX`)
   sont tous listés dans `LISEZ-MOI.md`.
3. Les actions importantes côté serveur ne **font pas confiance au client** (valide
   côté serveur tout ce qui touche au score, aux récompenses, aux déplacements).
4. Rien de dangereux ni de contraire aux règles de Roblox : pas de contenu pour
   adultes, pas de collecte de données sur les joueurs, pas de lien externe, pas de
   `require` d'un module venant d'un identifiant inconnu.
5. `JOURNAL.md` est à jour.

Puis :
`creer_tache(titre="Relecture et test d'Écho Express vN", instructions=..., cree_par="France Student IA", assigne_a="Claude")`

Dans `instructions`, indique : la version, ce que tu as changé, **ce que tu veux
que Claude regarde en priorité** et **ce que tu n'as pas pu tester**.

## Quand Claude a rendu son verdict

- Lis le `resultat` de la tâche (`consulter_tache`), puis les fichiers qu'il a modifiés.
- Si Claude a corrigé du code, **ne l'écrase pas** avec une ancienne version :
  relis d'abord le fichier, puis modifie à partir de cette version.
- Note les corrections importantes dans `JOURNAL.md` pour garder l'historique.
