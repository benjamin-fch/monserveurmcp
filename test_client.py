import asyncio

from mcp import Client


async def main() -> None:
    url = "http://127.0.0.1:8000/mcp"

    print(f"Connexion à {url}")

    async with Client(url) as client:
        tools = await client.list_tools()

        print("\nOutils disponibles :")

        for tool in tools.tools:
            print(f"- {tool.name}")

        resultat = await client.call_tool(
            "creer_tache",
            {
                "titre": "Première tâche",
                "instructions": (
                    "Créer une fiche de révision sur "
                    "la Révolution française."
                ),
                "cree_par": "Benjamin",
                "assigne_a": "Claude",
            },
        )

        print("\nTâche créée :")
        print(resultat.structured_content)

        liste = await client.call_tool(
            "lister_taches",
            {},
        )

        print("\nListe des tâches :")
        print(liste.structured_content)


if __name__ == "__main__":
    asyncio.run(main())
