import os
import threading
import uuid
from datetime import datetime, timezone

import uvicorn
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

import workspace
from auth import Authentificateur, MiddlewareAuth


mcp = MCPServer(
    "Serveur de tâches IA",
    instructions=(
        "Serveur permettant à plusieurs intelligences artificielles "
        "de créer, consulter, prendre et terminer des tâches, et de "
        "travailler sur des fichiers dans un espace de travail partagé "
        "(lister_fichiers, lire_fichier, ecrire_fichier...). Les chemins "
        "sont toujours relatifs à la racine de l'espace de travail. "
        "PREMIÈRE ACTION OBLIGATOIRE : appelle lire_guide avec le nom "
        "'00-demarrage' et suis ses consignes avant toute autre action."
    ),
)

tasks: dict[str, dict] = {}
tasks_lock = threading.Lock()


def maintenant() -> str:
    return datetime.now(timezone.utc).isoformat()


@mcp.tool()
def creer_tache(
    titre: str,
    instructions: str,
    cree_par: str = "utilisateur",
    assigne_a: str = "",
) -> dict:
    """
    Crée une nouvelle tâche partagée.

    Args:
        titre: Titre court de la tâche.
        instructions: Description du travail demandé.
        cree_par: Nom de la personne ou de l'IA qui crée la tâche.
        assigne_a: Nom facultatif de l'exécutant.
    """
    task_id = str(uuid.uuid4())
    date = maintenant()

    task = {
        "id": task_id,
        "titre": titre,
        "instructions": instructions,
        "statut": "a_faire",
        "cree_par": cree_par,
        "assigne_a": assigne_a or None,
        "resultat": None,
        "date_creation": date,
        "date_modification": date,
    }

    with tasks_lock:
        tasks[task_id] = task

    return task


@mcp.tool()
def lister_taches(statut: str = "") -> list[dict]:
    """
    Liste les tâches du serveur.

    Args:
        statut: Filtre facultatif : a_faire, en_cours ou terminee.
    """
    with tasks_lock:
        liste = list(tasks.values())

    if statut:
        liste = [
            task
            for task in liste
            if task["statut"] == statut
        ]

    return liste


@mcp.tool()
def consulter_tache(task_id: str) -> dict:
    """
    Consulte une tâche avec son identifiant.

    Args:
        task_id: Identifiant unique de la tâche.
    """
    with tasks_lock:
        task = tasks.get(task_id)

    if task is None:
        return {
            "succes": False,
            "erreur": "Tâche introuvable.",
            "task_id": task_id,
        }

    return {
        "succes": True,
        "tache": task,
    }


@mcp.tool()
def prendre_tache(task_id: str, executant: str) -> dict:
    """
    Attribue une tâche disponible à un exécutant.

    Args:
        task_id: Identifiant de la tâche.
        executant: Nom de l'IA ou de la personne exécutante.
    """
    with tasks_lock:
        task = tasks.get(task_id)

        if task is None:
            return {
                "succes": False,
                "erreur": "Tâche introuvable.",
            }

        if task["statut"] != "a_faire":
            return {
                "succes": False,
                "erreur": "Cette tâche n'est plus disponible.",
                "statut_actuel": task["statut"],
            }

        task["statut"] = "en_cours"
        task["assigne_a"] = executant
        task["date_modification"] = maintenant()

        return {
            "succes": True,
            "tache": task,
        }


@mcp.tool()
def deposer_resultat(
    task_id: str,
    resultat: str,
    executant: str,
) -> dict:
    """
    Enregistre le résultat d'une tâche.

    Args:
        task_id: Identifiant de la tâche.
        resultat: Résultat produit.
        executant: Nom de l'IA ou de la personne exécutante.
    """
    with tasks_lock:
        task = tasks.get(task_id)

        if task is None:
            return {
                "succes": False,
                "erreur": "Tâche introuvable.",
            }

        task["statut"] = "terminee"
        task["resultat"] = resultat
        task["assigne_a"] = executant
        task["date_modification"] = maintenant()

        return {
            "succes": True,
            "tache": task,
        }


# --- Guides d'utilisation pour les IA -----------------------------------


@mcp.tool()
def lire_guide(nom: str = "") -> dict:
    """
    Lit un guide d'utilisation du serveur. À APPELER EN PREMIER avec
    nom="00-demarrage". Sans nom, liste les guides disponibles.

    Args:
        nom: Nom du guide, par ex. "00-demarrage", "01-outils",
            "02-projet-echo-express", "03-conventions".
    """
    return _garde(workspace.lire_guide, nom)


# --- Espace de travail partagé : outils fichiers ------------------------


def _garde(fonction, *args, **kwargs) -> dict:
    """Exécute une opération fichier et uniformise les erreurs."""
    try:
        return {"succes": True, **fonction(*args, **kwargs)}
    except workspace.WorkspaceError as erreur:
        return {"succes": False, "erreur": str(erreur)}
    except OSError as erreur:
        return {"succes": False, "erreur": f"Erreur fichier : {erreur.strerror or erreur}"}


@mcp.tool()
def lister_fichiers(chemin: str = "", recursif: bool = False) -> dict:
    """
    Liste le contenu d'un dossier de l'espace de travail partagé.

    Args:
        chemin: Dossier relatif à la racine ("" = racine).
        recursif: Si vrai, liste aussi les sous-dossiers.
    """
    return _garde(workspace.lister, chemin, recursif)


@mcp.tool()
def lire_fichier(chemin: str, debut: int = 0, longueur: int = 200000) -> dict:
    """
    Lit un fichier texte (UTF-8) de l'espace de travail.

    Args:
        chemin: Chemin relatif du fichier.
        debut: Position du premier caractère à lire (pour les gros fichiers).
        longueur: Nombre maximal de caractères à renvoyer.
    """
    return _garde(workspace.lire, chemin, debut, longueur)


@mcp.tool()
def ecrire_fichier(chemin: str, contenu: str, ecraser: bool = True) -> dict:
    """
    Crée ou remplace un fichier texte. Les dossiers manquants sont créés.

    Args:
        chemin: Chemin relatif du fichier.
        contenu: Texte complet du fichier.
        ecraser: Si faux, refuse d'écraser un fichier existant.
    """
    return _garde(workspace.ecrire, chemin, contenu, ecraser)


@mcp.tool()
def ajouter_au_fichier(chemin: str, contenu: str) -> dict:
    """
    Ajoute du texte à la fin d'un fichier (le crée s'il n'existe pas).

    Args:
        chemin: Chemin relatif du fichier.
        contenu: Texte à ajouter.
    """
    return _garde(workspace.ajouter, chemin, contenu)


@mcp.tool()
def creer_dossier(chemin: str) -> dict:
    """
    Crée un dossier (et ses parents).

    Args:
        chemin: Chemin relatif du dossier.
    """
    return _garde(workspace.creer_dossier, chemin)


@mcp.tool()
def deplacer_fichier(source: str, destination: str) -> dict:
    """
    Déplace ou renomme un fichier ou un dossier.

    Args:
        source: Chemin relatif actuel.
        destination: Nouveau chemin relatif (ne doit pas exister).
    """
    return _garde(workspace.deplacer, source, destination)


@mcp.tool()
def supprimer_fichier(chemin: str) -> dict:
    """
    Supprime un fichier ou un dossier vide.

    Args:
        chemin: Chemin relatif à supprimer.
    """
    return _garde(workspace.supprimer, chemin)


@mcp.tool()
def chercher_dans_fichiers(texte: str, chemin: str = "") -> dict:
    """
    Cherche un texte (sans tenir compte de la casse) dans les fichiers texte.

    Args:
        texte: Texte à rechercher.
        chemin: Dossier ou fichier où chercher ("" = tout l'espace).
    """
    return _garde(workspace.chercher, texte, chemin)


# --- Routes HTTP : santé, connexion 2FA, synchronisation VS Code --------

auth: Authentificateur | None = None


@mcp.custom_route("/health", methods=["GET"])
async def sante(request: Request) -> Response:
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/auth/login", methods=["POST"])
async def connexion(request: Request) -> Response:
    try:
        donnees = await request.json()
        jeton = str(donnees.get("token", ""))
        code = str(donnees.get("code", ""))
    except Exception:
        return JSONResponse({"erreur": "Requête invalide."}, status_code=400)

    session, message = auth.connexion(jeton, code)
    if session is None:
        statut = 429 if message.startswith("Trop") else 401
        return JSONResponse({"erreur": message}, status_code=statut)
    return JSONResponse(
        {"session_token": session, "expires_in": auth.duree_session}
    )


@mcp.custom_route("/workspace.zip", methods=["GET"])
async def archive(request: Request) -> Response:
    try:
        contenu = workspace.archive_zip()
    except workspace.WorkspaceError as erreur:
        return JSONResponse({"erreur": str(erreur)}, status_code=413)
    return Response(
        contenu,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="workspace.zip"'},
    )


def creer_app():
    """Construit l'application ASGI protégée par la double authentification."""
    global auth
    auth = Authentificateur()  # refuse de démarrer si les secrets manquent
    workspace.racine()
    workspace.publier_guides()

    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        transport_security=security,
        host="0.0.0.0",
    )
    return MiddlewareAuth(app, auth)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(
        creer_app(),
        host="0.0.0.0",
        port=port,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
