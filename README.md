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

Guides : `lire_guide` (à appeler en premier par l'IA, voir ci-dessous).
Tâches : `creer_tache`, `lister_taches`, `consulter_tache`, `prendre_tache`, `deposer_resultat`.
Fichiers : `lister_fichiers`, `lire_fichier`, `ecrire_fichier`, `ajouter_au_fichier`,
`creer_dossier`, `deplacer_fichier`, `supprimer_fichier`, `chercher_dans_fichiers`.
Sécurité : `analyser_lien` (bac à sable pour liens suspects, voir section 6).

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

## 6. Bac à sable : vérifier un lien suspect (`analyser_lien`)

Une IA connectée (Claude, France Student IA, VS Code) peut vérifier un lien **sans que
tu l'ouvres** : c'est le serveur Render qui va voir le site, en lecture seule.

- **Isolé de ton téléphone** : rien n'est ouvert chez toi.
- **Passif** : la page est lue comme du texte, son JavaScript n'est jamais exécuté,
  rien n'est téléchargé ni installé, aucun cookie.
- **Le serveur est protégé** : adresses internes refusées à chaque redirection
  (anti-SSRF), ports 80/443/8080/8443 seulement, 1,5 Mo et 20 s max par page.
- **Ce qui est vérifié** : imitation de marques (Ameli, impots, La Poste, banques,
  PayPal…), fautes de frappe volontaires (`paypa1`), lettres cyrilliques sosies,
  faux « gouv », âge du domaine (créé il y a 3 jours ?), extension douteuse,
  certificat, redirections cachées, liens raccourcis, champs carte bancaire / code SMS,
  formulaire envoyé vers un autre site, robot Telegram de kit de phishing, ton
  pressant, téléchargement d'APK ou de profil iPhone.
- Résultat : 🔴 DANGEREUX / 🟠 SUSPECT / 🟢 AUCUN SIGNAL D'ALERTE + raisons + conseil.

**Options (gratuites, recommandées)** — ajoute dans Render > Environment :

| Variable | Apporte | Où l'obtenir |
|---|---|---|
| `URLSCAN_API_KEY` | un **vrai navigateur isolé** ouvre le site + **capture d'écran** | compte gratuit sur urlscan.io > Settings & API |
| `GOOGLE_SAFE_BROWSING_KEY` | listes noires de Google | Google Cloud Console > activer « Safe Browsing API » > clé d'API |
| `VIRUSTOTAL_API_KEY` | avis de ~90 antivirus | compte gratuit sur virustotal.com > API key |
| `URLSCAN_VISIBILITE` | `unlisted` (défaut) ou `private`/`public` | — |

Sans clé, l'analyse locale fonctionne quand même.

Le code est rangé dans le sous-projet `verificateur_liens/` (voir son `LISEZ-MOI.md`).
En ligne de commande : `python -m verificateur_liens.analyse_lien "https://lien-suspect"`.
Tests (sans Internet, avec un faux site de phishing local) : `python -m unittest verificateur_liens.test_analyse_lien`.

## Limites connues

- Les clients qui ne peuvent pas envoyer d'en-tête `Authorization` ne peuvent pas
  se connecter (c'est le prix de la sécurité). C'est à vérifier pour France Student IA.
- `pull_workspace.py` va dans un seul sens (serveur → ordinateur).
- `analyser_lien` repère les arnaques courantes mais ne garantit rien : certains sites
  piégés montrent une page innocente aux robots. 🟢 ne veut pas dire « garanti sûr ».
