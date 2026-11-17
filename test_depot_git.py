"""Test de la sauvegarde GitHub, avec un dépôt « distant » local (aucun réseau).

    python test_depot_git.py

Simule deux vies du serveur (comme un redémarrage Render qui efface le disque) :
les fichiers et les tâches écrits pendant la première doivent réapparaître dans
la seconde. Vérifie aussi la récupération d'une modification faite ailleurs.
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ICI = Path(__file__).parent
TMP = Path(tempfile.mkdtemp())
DISTANT = TMP / "distant.git"
subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(DISTANT)], check=True)

ENV = {
    **os.environ,
    "MCP_API_TOKEN": "t" * 40,
    "MCP_TOTP_SECRET": "JBSWY3DPEHPK3PXPJBSWY3DP",
    "PUBLIC_URL": "http://localhost:8000",
    "GIT_REMOTE_URL": str(DISTANT),
    "GITHUB_BRANCH": "main",
}


def vie(nom: str, code: str) -> str:
    """Lance une « vie » du serveur dans un processus séparé, disque vierge."""
    env = {**ENV, "WORKSPACE_DIR": str(TMP / nom)}
    script = textwrap.dedent(
        """
        import json, sys
        import server
        from depot_git import depot
        server.creer_app()
        """
    ) + textwrap.dedent(code) + "\ndepot.arreter()\n"
    r = subprocess.run([sys.executable, "-c", script], cwd=ICI, env=env, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        print(r.stderr[-2000:])
        raise SystemExit(f"ÉCHEC : la vie {nom} a planté")
    return r.stdout


def verifier(condition: bool, message: str) -> None:
    print(("OK   " if condition else "ÉCHEC") + " " + message)
    if not condition:
        raise SystemExit(1)


def git_distant(*args: str) -> str:
    return subprocess.run(["git", "--git-dir", str(DISTANT), *args], capture_output=True, text=True).stdout


# Vie 1 : les IA écrivent
sortie = vie("vie1", """
    print(json.dumps(server.ecrire_fichier("projet/notes.md", "# Notes\\nde France Student IA\\n")))
    print(json.dumps(server.creer_dossier("vide")))
    print(json.dumps(server.ecrire_fichier(".git/hooks/post-commit", "rm -rf /")))
    print(json.dumps(server.lire_fichier(".git/config")))
    print(json.dumps(server.ecrire_fichier(".GIT/config", "x")))
    print(json.dumps(server.ecrire_fichier("a/.git./hooks/x", "x")))
    t = server.creer_tache("Relire les notes", "Vérifie projet/notes.md", "France Student IA")
    print(json.dumps(server.prendre_tache(t["id"], "Claude")))
    print(json.dumps(server.lister_fichiers("", True)))
""")
lignes = [json.loads(ligne) for ligne in sortie.strip().splitlines()]
verifier(lignes[0]["succes"], "écriture d'un fichier")
verifier(not lignes[2]["succes"] and ".git" in lignes[2]["erreur"], "écriture dans .git refusée")
verifier(not lignes[3]["succes"], "lecture de .git refusée")
verifier(not lignes[4]["succes"] and not lignes[5]["succes"], "variantes .GIT et .git. refusées")
verifier(not (TMP / "vie1" / ".git").exists() and (TMP / "vie1.depot-git" / "HEAD").is_file(),
         "dépôt git rangé hors de l'espace de travail")
chemins = [e["chemin"] for e in lignes[7]["entrees"]]
verifier(not any(c == ".git" or c.startswith(".git/") for c in chemins) and "vide" in chemins and "vide/.gitkeep" not in chemins,
         "listing sans .git ni .gitkeep, dossier vide visible")

journal = git_distant("log", "--format=%s", "main")
verifier("notes.md" in git_distant("ls-tree", "-r", "--name-only", "main"), "fichier poussé sur le dépôt distant")
verifier(journal.strip() != "", f"commits poussés :\n     " + journal.strip().replace("\n", "\n     "))

# Quelqu'un modifie le dépôt ailleurs (toi depuis VS Code)
clone = TMP / "clone-perso"
subprocess.run(["git", "clone", "-q", str(DISTANT), str(clone)], check=True)
(clone / "projet" / "de-benjamin.md").write_text("Ajouté depuis VS Code\n", encoding="utf-8")
subprocess.run(["git", "-C", str(clone), "add", "-A"], check=True)
subprocess.run(["git", "-C", str(clone), "-c", "user.name=B", "-c", "user.email=b@x", "commit", "-q", "-m", "perso"], check=True)
subprocess.run(["git", "-C", str(clone), "push", "-q"], check=True)

# Vie 2 : disque vierge (redémarrage Render) -> tout doit revenir
sortie = vie("vie2", """
    print(json.dumps(server.lire_fichier("projet/notes.md")))
    print(json.dumps(server.lire_fichier("projet/de-benjamin.md")))
    print(json.dumps(server.lister_taches()))
    print(json.dumps(server.lister_fichiers("vide")))
    print(json.dumps(server.ajouter_au_fichier("projet/notes.md", "relu par Claude\\n")))
""")
lignes = [json.loads(ligne) for ligne in sortie.strip().splitlines()]
verifier(lignes[0]["succes"] and "France Student" in lignes[0]["contenu"], "fichier retrouvé après redémarrage")
verifier(lignes[1]["succes"], "modification faite depuis VS Code récupérée")
verifier(len(lignes[2]) == 1 and lignes[2][0]["statut"] == "en_cours", "tâche retrouvée avec son statut")
verifier(lignes[3]["succes"], "dossier vide conservé")
verifier("relu par Claude" in git_distant("show", "main:projet/notes.md"), "modification de la vie 2 poussée")

print("\nTous les tests passent.")
