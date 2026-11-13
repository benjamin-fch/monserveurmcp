"""Télécharge l'espace de travail du serveur dans un dossier local, pour l'ouvrir dans VS Code.

    python pull_workspace.py                 # -> ./workspace-local
    python pull_workspace.py mon-dossier     # -> ./mon-dossier
    code workspace-local                     # ouvre les fichiers créés par l'autre IA

Les fichiers locaux de même nom sont remplacés par ceux du serveur. Rien n'est
supprimé côté local. Les modifications faites dans VS Code ne remontent PAS vers
le serveur : pour cela, demande à Claude (via les outils MCP) de les relire ou
de les écrire.
"""

import io
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from login import obtenir_session, url_serveur


def extraire_sans_risque(archive: zipfile.ZipFile, destination: Path) -> int:
    destination = destination.resolve()
    nombre = 0
    for info in archive.infolist():
        cible = (destination / info.filename).resolve()
        if destination not in cible.parents:
            print(f"Ignoré (chemin suspect) : {info.filename}")
            continue
        if info.is_dir():
            cible.mkdir(parents=True, exist_ok=True)
            continue
        cible.parent.mkdir(parents=True, exist_ok=True)
        cible.write_bytes(archive.read(info))
        nombre += 1
    return nombre


def main() -> None:
    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "workspace-local")
    url = url_serveur()
    session = obtenir_session(url)

    requete = urllib.request.Request(
        f"{url}/workspace.zip", headers={"Authorization": f"Bearer {session}"}
    )
    try:
        with urllib.request.urlopen(requete, timeout=120) as reponse:
            contenu = reponse.read()
    except urllib.error.HTTPError as erreur:
        sys.exit(f"Téléchargement refusé ({erreur.code}).")

    with zipfile.ZipFile(io.BytesIO(contenu)) as archive:
        destination.mkdir(parents=True, exist_ok=True)
        nombre = extraire_sans_risque(archive, destination)
    print(f"{nombre} fichier(s) dans {destination.resolve()}")
    print(f"Ouvre-le dans VS Code :  code {destination}")


if __name__ == "__main__":
    main()
