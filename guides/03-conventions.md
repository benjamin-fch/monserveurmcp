# Conventions de fichiers

## Noms

- Dossiers et fichiers en **minuscules, sans espaces ni accents**, avec des tirets :
  `echo-express`, `plan-niveau-1.md`. (Exception : les noms de scripts Roblox
  peuvent suivre le style Roblox, par ex. `GameManager.server.lua`.)
- Documents : `.md` (Markdown). Code : l'extension du langage (`.lua`, `.py`, `.js`, `.html`).
- Pas de copies du genre `fichier-final-v2-vraiment-final.md`. Garde **une** version
  à jour et note l'historique dans `JOURNAL.md`.

## Où ranger quoi

| Contenu | Où |
|---|---|
| Un projet | Son propre dossier à la racine |
| Code | `<projet>/src/` |
| Notes, idées, recherches | `<projet>/notes/` |
| Résumé et état du projet | `<projet>/LISEZ-MOI.md` |
| Historique des changements | `<projet>/JOURNAL.md` |
| Tout ce qui est temporaire | `brouillons/` (à nettoyer régulièrement) |

N'écris rien dans `_guides/` : ce dossier est recopié par le serveur et tes
changements y seraient perdus.

## Format de `JOURNAL.md`

Le plus récent en haut :

```
## 2026-11-13 — v2 (France Student IA)
- Ajouté : système de score côté serveur
- Corrigé : le joueur pouvait sauter la porte de départ
- Non testé : la musique d'ambiance
```

## Style d'écriture

- Écris en **français**, simple et direct.
- Titres courts, listes quand il y a plusieurs éléments, tableaux pour comparer.
- Dis ce qui est **fait**, ce qui est **à faire**, ce qui est **incertain** — séparément.
- Pour une décision qui revient à Benj, pose la question dans `LISEZ-MOI.md`
  (section « Questions ouvertes ») **et** dis-le-lui dans la conversation.

## Ce que tu ne dois jamais faire

- Écrire un mot de passe, une clé, un jeton ou une donnée personnelle dans un fichier.
- Supprimer ou renommer des fichiers que tu n'as pas créés, sans l'accord de Benj.
- Marquer une tâche comme terminée si le travail est partiel : décris l'état réel.
- Inventer des résultats de test, des chiffres ou des sources.
