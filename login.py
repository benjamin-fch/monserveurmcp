"""Connexion au serveur avec la double authentification (jeton + code TOTP).

    python login.py            # affiche un jeton de session (valable 12 h)

Configuration (variables d'environnement ou fichier .env à côté du script) :
    MCP_URL         ex. https://mon-service.onrender.com
    MCP_API_TOKEN   le jeton secret (facteur 1)
Le code à 6 chiffres (facteur 2) est demandé à chaque connexion.

Utilisé aussi par pull_workspace.py et test_client.py. Bibliothèque standard
uniquement, pour que les scripts tournent partout.
"""

import getpass
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def charger_env() -> None:
    """Lit un fichier .env simple (CLE=valeur) sans écraser l'environnement."""
    fichier = Path(__file__).parent / ".env"
    if not fichier.exists():
        return
    for ligne in fichier.read_text(encoding="utf-8").splitlines():
        ligne = ligne.strip()
        if ligne and not ligne.startswith("#") and "=" in ligne:
            cle, valeur = ligne.split("=", 1)
            os.environ.setdefault(cle.strip(), valeur.strip().strip('"').strip("'"))


def url_serveur() -> str:
    charger_env()
    url = os.environ.get("MCP_URL", "").rstrip("/")
    if not url:
        url = input("URL du serveur (ex. https://mon-service.onrender.com) : ").strip().rstrip("/")
    if url.endswith("/mcp"):
        url = url[: -len("/mcp")]
    return url


def obtenir_session(url: str, code: str | None = None) -> str:
    charger_env()
    jeton = os.environ.get("MCP_API_TOKEN") or getpass.getpass("Jeton secret (MCP_API_TOKEN) : ")
    code = code or input("Code à 6 chiffres de l'application d'authentification : ").strip()

    requete = urllib.request.Request(
        f"{url}/auth/login",
        data=json.dumps({"token": jeton, "code": code}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(requete, timeout=60) as reponse:
            return json.load(reponse)["session_token"]
    except urllib.error.HTTPError as erreur:
        try:
            message = json.load(erreur).get("erreur", erreur.reason)
        except Exception:
            message = erreur.reason
        sys.exit(f"Connexion refusée ({erreur.code}) : {message}")
    except urllib.error.URLError as erreur:
        sys.exit(f"Serveur injoignable : {erreur.reason} (Render gratuit : réessaie dans 1 minute, il se réveille)")


if __name__ == "__main__":
    print(obtenir_session(url_serveur()))
