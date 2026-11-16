# Serveur MCP — tâches IA + espace de travail partagé

Serveur MCP (Python) qui permet à plusieurs IA (France Student IA, Claude…) de :
- gérer des **tâches** partagées (créer, prendre, déposer un résultat) ;
- **lire, écrire, chercher et organiser des fichiers** dans un espace de travail commun ;

et à toi de **retrouver ces fichiers dans VS Code**. Tout est protégé par une
**passkey** (Touch ID / Face ID) via OAuth.

## 1. Mise en place sur Render (une seule fois)

1. En local : `pip install -r requirements.txt` puis `python setup_2fa.py`.
   Le script affiche deux secrets et le moyen de les ajouter à ton application
   d'authentification (Google Authenticator, Authy, 1Password…).
2. Sur Render, service > **Environment**, ajoute :
   | Variable | Valeur |
   |---|---|
   | `MCP_API_TOKEN` | le jeton affiché |
   | `MCP_TOTP_SECRET` | la clé TOTP affichée |
   | `WORKSPACE_DIR` | `/data/workspace` (voir ci-dessous) |
   | `PASSKEYS` | vide au départ (rempli à l'étape 3) |
   L'URL publique est lue dans `RENDER_EXTERNAL_URL` (fourni par Render) ;
   `PUBLIC_URL` la remplace si tu utilises un domaine personnalisé.
3. **Enregistre ta passkey** : ouvre `https://TON-SERVICE.onrender.com/passkey/installer`
   sur ton Mac, saisis le jeton secret et le code à 6 chiffres, puis Touch ID.
   La page affiche une valeur : colle-la dans la variable `PASSKEYS` et enregistre
   (Render redéploie). Une passkey iCloud fonctionne aussi sur iPhone (Face ID).
   Pour ajouter un appareil, refais l'étape : la valeur contient alors toutes les passkeys.
4. **Disque persistant** : sur l'offre gratuite de Render, le disque est effacé à
   chaque redémarrage. Ajoute un *Disk* monté sur `/data` (offre payante), sinon
   les fichiers créés par les IA disparaîtront. Les passkeys et les connexions,
   elles, survivent aux redémarrages.
5. Commande de démarrage : `python server.py` (inchangée).

⚠️ Le serveur **refuse de démarrer** si `MCP_API_TOKEN` ou `MCP_TOTP_SECRET` manque.

## 2. Comment les IA se connectent (OAuth + passkey)

Le serveur est son propre serveur d'autorisation **OAuth 2.1**, comme l'attend MCP :

1. L'IA découvre l'authentification (`/.well-known/oauth-protected-resource/mcp`),
   s'enregistre (`/register`), puis ouvre une fenêtre de connexion.
2. La fenêtre affiche « Autoriser <nom de l'IA> » : un geste **Touch ID / Face ID** suffit.
3. L'IA reçoit un jeton d'accès (1 h) et un jeton de renouvellement (90 jours),
   renouvelé automatiquement. Plus de code à recopier.

Sécurité : PKCE obligatoire, codes et défis à usage unique, passkey liée au domaine
du serveur (inutilisable sur un site pirate), vérification biométrique exigée.
Clients, codes et jetons sont **signés** (aucun stockage) : un redémarrage ne
déconnecte personne. **Tout révoquer** : modifier `PASSKEYS` ou l'un des secrets
(ajouter une passkey déconnecte donc aussi les IA, qui se reconnecteront d'un geste).

Transports : `/mcp` (HTTP streamable, recommandé) et `/sse` (ancien SSE), même authentification.

## 3. Brancher une IA

| IA | Réglage |
|---|---|
| **France Student IA** | Réglages > MCP : nom `serveur-ia`, URL `https://TON-SERVICE.onrender.com/mcp`, authentification « Connexion avec votre compte » |
| **Claude Code** | `claude mcp add --transport http --scope user serveur-ia https://TON-SERVICE.onrender.com/mcp` puis `/mcp` > serveur-ia > Authenticate |
| **claude.ai** | Réglages > Connecteurs > Ajouter un connecteur personnalisé, avec l'URL `/mcp` |
| **VS Code** | `.vscode/mcp.json` (URL seule) : VS Code ouvre la fenêtre de connexion |

**Scripts locaux** (inchangés, avec la double authentification) : crée un `.env` à
côté de `login.py` (ignoré par Git) avec `MCP_URL` et `MCP_API_TOKEN`, puis :

| Besoin | Commande |
|---|---|
| Obtenir un jeton de session (12 h) | `python login.py` |
| Télécharger les fichiers des IA | `python pull_workspace.py` puis `code workspace-local` |
| Tester le serveur | `python test_client.py` |
| Tester OAuth + passkey en local | `python test_oauth_passkey.py` |

## 4. Outils exposés

Guides : `lire_guide` (à appeler en premier par l'IA, voir ci-dessous).
Tâches : `creer_tache`, `lister_taches`, `consulter_tache`, `prendre_tache`, `deposer_resultat`.
Fichiers : `lister_fichiers`, `lire_fichier`, `ecrire_fichier`, `ajouter_au_fichier`,
`creer_dossier`, `deplacer_fichier`, `supprimer_fichier`, `chercher_dans_fichiers`.

Les chemins sont relatifs à `WORKSPACE_DIR` ; `..`, chemins absolus et liens
symboliques sortants sont refusés. Limites : 2 Mo par écriture, 5 Mo par lecture,
200 Mo au total (`WORKSPACE_MAX_BYTES`).

Les tâches restent en mémoire : elles sont perdues au redémarrage.

## 5. Guides pour les IA

Le dossier `guides/` explique à France Student IA comment travailler avec le serveur :
`00-demarrage` (rôles et règles), `01-outils` (mode d'emploi), `02-projets` (mener
n'importe quel projet et passer le relais à Claude), `03-conventions` (nommage, journal)
et un guide **par projet** nommé `projet-<nom>.md` (aujourd'hui : `projet-echo-express`,
le jeu Roblox). Roblox n'est qu'un projet parmi d'autres.
- Les instructions du serveur demandent à l'IA d'appeler `lire_guide("00-demarrage")` d'abord.
- Au démarrage, les guides sont aussi copiés dans `_guides/` de l'espace de travail :
  tu les vois dans VS Code après `python pull_workspace.py`.
- Pour modifier un guide ou en ajouter un (nouveau projet) : édite/crée `guides/*.md`
  dans le dépôt et redéploie. Il apparaît tout seul dans `lire_guide()`.
- Dans une conversation normale (sans connexion MCP), colle-lui simplement le contenu de `00-demarrage.md`.

## Limites connues

- Pas de révocation individuelle d'un jeton (voir « Tout révoquer » ci-dessus).
- `pull_workspace.py` va dans un seul sens (serveur → ordinateur).
