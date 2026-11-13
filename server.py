import os
import threading
import uuid
from datetime import datetime, timezone

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings


mcp = MCPServer(
    "Serveur de tâches IA",
    instructions=(
        "Serveur permettant à plusieurs intelligences artificielles "
        "de créer, consulter, prendre et terminer des tâches."
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))

    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )

    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port,
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        transport_security=security,
    )
