# Serveur MCP — tâches IA + espace de travail partagé

Serveur MCP (Python) qui permet à plusieurs IA (France Student IA, Claude…) de :
- gérer des **tâches** partagées (créer, prendre, déposer un résultat) ;
- **lire, écrire, chercher et organiser des fichiers** dans un espace de travail commun ;

et à toi de **retrouver ces fichiers dans VS Code**. Tout est protégé par une
**double authentification** : jeton secret + code à 6 chiffres.

## 1. Mise en place sur Render (une seule fois)

1. En local : `pip install -r requirements.txt` puis `python setup_2fa.py`.
   Le script affiche deux secrets et le moyen de les ajouter à ton application
   d'authentification (Google Authenticator, Authy, 1Password…).
2. Sur Render, service > **Environment**, ajoute :
   | Variable | Valeur |
   |---|---|
   | `MCP_API_TOKEN` | le jeton affiché (facteur 1) |
   | `MCP_TOTP_SECRET` | la clé TOTP affichée (facteur 2) |
   | `WORKSPACE_DIR` | `/data/workspace` (voir ci-dessous) |
3. **Disque persistant** : sur l'offre gratuite de Render, le disque est effacé à
   chaque redémarrage. Ajoute un *Disk* monté sur `/data` (offre payante), sinon
   les fichiers créés par les IA disparaîtront.
4. Commande de démarrage : `python server.py` (inchangée).

⚠️ Le serveur **refuse de démarrer** si `MCP_API_TOKEN` ou `MCP_TOTP_SECRET`
manque : ajoute les variables **avant** de déployer cette version.

## 2. Comment fonctionne la double authentification

1. Le client envoie `POST /auth/login` avec `{"token": "<jeton>", "code": "<6 chiffres>"}`.
2. Si les deux sont corrects, le serveur renvoie un **jeton de session** valable
   12 h (`SESSION_TTL_SECONDS` pour changer).
3. Toutes les autres routes (`/mcp`, `/workspace.zip`) exigent
   `Authorization: Bearer <jeton de session>`. Seuls `/health` et `/auth/login` sont publics.

Protections : comparaison à temps constant, même message d'erreur pour les deux
facteurs, code TOTP non rejouable, blocage 10 min après 8 échecs, sessions
signées (changer un secret les invalide toutes), rien dans les logs.

## 3. Utilisation depuis ton ordinateur

Crée un fichier `.env` à côté de `login.py` (ignoré par Git) :
```
MCP_URL=https://TON-SERVICE.onrender.com
MCP_API_TOKEN=le-jeton-secret
```

| Besoin | Commande |
|---|---|
| Obtenir un jeton de session | `python login.py` (demande le code à 6 chiffres) |
| Télécharger les fichiers des IA | `python pull_workspace.py` puis `code workspace-local` |
| Tester le serveur | `python test_client.py` |

**VS Code (agent / Copilot)** : remplace l'URL dans `.vscode/mcp.json`, lance
« MCP: List Servers » > `serveur-ia` > Start ; VS Code te demande le jeton de
session (celui de `python login.py`). Les outils du serveur sont alors
utilisables dans le chat de VS Code.

**Claude Code** :
```
claude mcp add --transport http serveur-ia https://TON-SERVICE.onrender.com/mcp \
  --header "Authorization: Bearer $(python login.py)"
```
À refaire quand la session expire (12 h).

## 4. Outils exposés

Tâches : `creer_tache`, `lister_taches`, `consulter_tache`, `prendre_tache`, `deposer_resultat`.
Fichiers : `lister_fichiers`, `lire_fichier`, `ecrire_fichier`, `ajouter_au_fichier`,
`creer_dossier`, `deplacer_fichier`, `supprimer_fichier`, `chercher_dans_fichiers`.

Les chemins sont relatifs à `WORKSPACE_DIR` ; `..`, chemins absolus et liens
symboliques sortants sont refusés. Limites : 2 Mo par écriture, 5 Mo par lecture,
200 Mo au total (`WORKSPACE_MAX_BYTES`).

Les tâches restent en mémoire : elles sont perdues au redémarrage.

## Limites connues

- Les clients qui ne peuvent pas envoyer d'en-tête `Authorization` ne peuvent pas
  se connecter (c'est le prix de la sécurité). C'est à vérifier pour France Student IA.
- `pull_workspace.py` va dans un seul sens (serveur → ordinateur).
