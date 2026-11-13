"""Test de bout en bout du serveur (local ou Render), avec la double authentification.

    # serveur local
    MCP_API_TOKEN=... MCP_TOTP_SECRET=... python server.py
    # autre terminal
    MCP_URL=http://127.0.0.1:8000 MCP_API_TOKEN=... python test_client.py

Le code TOTP est demandé au clavier (ou lu dans TEST_TOTP_CODE).
"""

import asyncio
import json
import os

from mcp import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from login import obtenir_session, url_serveur


def donnees(resultat) -> dict:
    """Résultat d'outil sous forme de dict (structuré ou JSON dans le texte)."""
    if resultat.structured_content is not None:
        return resultat.structured_content
    return json.loads(resultat.content[0].text)


async def main() -> None:
    url = url_serveur()
    session = obtenir_session(url, os.environ.get("TEST_TOTP_CODE"))
    print(f"Connecté à {url}")

    http = create_mcp_http_client(headers={"Authorization": f"Bearer {session}"})
    async with http:
        transport = streamable_http_client(f"{url}/mcp", http_client=http)
        async with Client(transport) as client:
            outils = await client.list_tools()
            print("\nOutils disponibles :")
            for outil in outils.tools:
                print(f"- {outil.name}")

            r = await client.call_tool(
                "ecrire_fichier",
                {"chemin": "test/bonjour.md", "contenu": "# Bonjour\nÉcrit par test_client.py\n"},
            )
            print("\necrire_fichier :", donnees(r))

            r = await client.call_tool("lister_fichiers", {"recursif": True})
            print("lister_fichiers :", donnees(r))

            r = await client.call_tool("lire_fichier", {"chemin": "test/bonjour.md"})
            print("lire_fichier :", donnees(r))

            r = await client.call_tool("lire_fichier", {"chemin": "../../etc/passwd"})
            print("évasion de chemin (doit être refusée) :", donnees(r))

            r = await client.call_tool(
                "creer_tache",
                {
                    "titre": "Première tâche",
                    "instructions": "Créer une fiche de révision sur la Révolution française.",
                    "cree_par": "Benjamin",
                    "assigne_a": "Claude",
                },
            )
            print("\ncreer_tache :", donnees(r))


if __name__ == "__main__":
    asyncio.run(main())
