# Mode d'emploi des outils

Tous les chemins sont **relatifs à la racine de l'espace de travail** :
écris `echo-express/LISEZ-MOI.md`, jamais `/echo-express/...` ni `../`.
Chaque outil renvoie `succes: true` ou `succes: false` avec une `erreur` lisible :
**lis toujours `succes`** avant de continuer.

## Fichiers

| Outil | Usage |
|---|---|
| `lister_fichiers(chemin="", recursif=false)` | Voir le contenu d'un dossier. Utilise `recursif=true` pour tout voir. |
| `lire_fichier(chemin, debut=0, longueur=200000)` | Lire un fichier texte. Si `tronque` est vrai, relis avec `debut` plus grand. |
| `ecrire_fichier(chemin, contenu, ecraser=true)` | Créer ou **remplacer** un fichier (les dossiers manquants sont créés). |
| `ajouter_au_fichier(chemin, contenu)` | Ajouter à la fin (journal, liste de changements). |
| `creer_dossier(chemin)` | Créer un dossier. |
| `deplacer_fichier(source, destination)` | Déplacer ou renommer (la destination ne doit pas exister). |
| `supprimer_fichier(chemin)` | Supprimer un fichier ou un dossier **vide**. |
| `chercher_dans_fichiers(texte, chemin="")` | Chercher un mot dans les fichiers texte. |

Conseils :
- Avant d'écraser un fichier, **relis-le** : Claude ou Benj l'a peut-être modifié.
  Pour ne rien écraser par erreur, utilise `ecraser=false`.
- Un fichier fait au maximum **2 Mo** par écriture. Découpe les gros contenus.
- Seuls les fichiers **texte UTF-8** sont lisibles (pas d'images ni de binaires).
- Écris des fichiers **complets** : pas de `...` ni de « le reste est inchangé ».

## Tâches

C'est le canal officiel pour te passer le travail avec Claude.

| Outil | Usage |
|---|---|
| `creer_tache(titre, instructions, cree_par, assigne_a="")` | Demander quelque chose. |
| `lister_taches(statut="")` | `a_faire`, `en_cours` ou `terminee`. Vide = toutes. |
| `consulter_tache(task_id)` | Détail d'une tâche et son résultat. |
| `prendre_tache(task_id, executant)` | Se l'attribuer avant de commencer. |
| `deposer_resultat(task_id, resultat, executant)` | La terminer avec un compte rendu. |

Règles :
- `cree_par` et `executant` valent toujours **`"France Student IA"`** pour toi,
  **`"Claude"`** pour Claude, **`"Benj"`** pour Benj.
- Appelle `prendre_tache` **avant** de travailler, pour que personne ne la fasse en double.
- Le `resultat` est un **résumé court** qui pointe vers les fichiers
  (ex. « Code dans `echo-express/src/`, détails dans `echo-express/LISEZ-MOI.md` »).
  Le contenu lui-même va dans les fichiers, pas dans le résultat.
- Les tâches sont **en mémoire** : elles disparaissent si le serveur redémarre.
  Ce qui compte doit aussi figurer dans `LISEZ-MOI.md`.

## Exemple de passage de relais

1. Tu écris le code dans `echo-express/src/...` et tu mets à jour `echo-express/LISEZ-MOI.md`.
2. Tu appelles :
   `creer_tache(titre="Relecture et test d'Écho Express v1", instructions="Relire echo-express/src/, tester dans Roblox Studio, lister les bugs. Points douteux : le système de score (voir LISEZ-MOI).", cree_par="France Student IA", assigne_a="Claude")`
3. Claude prend la tâche, relit, corrige, puis dépose son résultat.
4. Tu relis le résultat avec `consulter_tache`, puis les fichiers modifiés.

## Si un outil renvoie une erreur

- « Chemin refusé » : tu as utilisé `..` ou un chemin absolu. Utilise un chemin relatif.
- « Le fichier existe déjà » : tu avais mis `ecraser=false`. Relis-le d'abord.
- « Quota dépassé » ou « trop volumineux » : réduis le contenu et préviens Benj.
- Erreur d'authentification (401) : la session a expiré (12 h). **Dis-le à Benj** ;
  tu ne peux pas la renouveler toi-même.
