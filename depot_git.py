"""Sauvegarde de l'espace de travail dans un dépôt GitHub privé.

Render (offre gratuite) efface le disque à chaque redémarrage. Avec ce module :
  - au démarrage, le serveur clone le dépôt dans WORKSPACE_DIR ;
  - après chaque écriture d'une IA, il commite et pousse (regroupé sur ~2 s) ;
  - toutes les minutes, il récupère les modifications faites ailleurs
    (par toi depuis VS Code ou github.com).

Variables d'environnement :
  GITHUB_REPO    propriétaire/nom du dépôt (ex. benjamin-fch/serveur-ia-workspace)
  GITHUB_TOKEN   jeton « fine-grained » limité à ce dépôt, droit Contents: read & write
  GITHUB_BRANCH  branche (défaut : main)
  GIT_REMOTE_URL (tests) URL complète du dépôt distant, remplace GITHUB_REPO

Sans GITHUB_REPO ni GIT_REMOTE_URL, le module est inactif (fichiers locaux seulement).
Le jeton n'est jamais écrit sur disque ni passé en argument de commande : il est
transmis à git par variables d'environnement (GIT_CONFIG_*).
"""

import atexit
import base64
import logging
import os
import subprocess
import threading
import time
from pathlib import Path

journal = logging.getLogger("depot_git")

DELAI_REGROUPEMENT = 2.0
INTERVALLE_RECUPERATION = 60.0
AUTEUR = ("Serveur IA", "serveur-ia@users.noreply.github.com")


class Depot:
    def __init__(self) -> None:
        self.verrou = threading.RLock()  # partagé avec les opérations de fichiers
        self._verrou_sync = threading.Lock()  # une seule synchronisation à la fois
        self._evenement = threading.Event()
        self._sale = False
        self._messages: list[str] = []
        self._arret = False
        self.actif = False
        self.dossier: Path | None = None
        self.dossier_git: Path | None = None
        self.derniere_erreur: str | None = None

        repo = os.environ.get("GITHUB_REPO", "").strip()
        self._url = os.environ.get("GIT_REMOTE_URL", "").strip() or (
            f"https://github.com/{repo}.git" if repo else ""
        )
        self._branche = os.environ.get("GITHUB_BRANCH", "main").strip() or "main"
        self._jeton = os.environ.get("GITHUB_TOKEN", "").strip()

    # --- git ----------------------------------------------------------------
    def _env(self) -> dict:
        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            # Le dépôt git vit HORS de l'espace de travail : les outils fichiers
            # des IA ne peuvent jamais atteindre sa configuration.
            "GIT_DIR": str(self.dossier_git),
            "GIT_WORK_TREE": str(self.dossier),
            "GIT_AUTHOR_NAME": AUTEUR[0],
            "GIT_AUTHOR_EMAIL": AUTEUR[1],
            "GIT_COMMITTER_NAME": AUTEUR[0],
            "GIT_COMMITTER_EMAIL": AUTEUR[1],
            # Désactive les hooks : personne ne doit pouvoir exécuter de code via le dépôt.
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": "/dev/null",
        }
        if self._jeton:
            identifiants = base64.b64encode(f"x-access-token:{self._jeton}".encode()).decode()
            env["GIT_CONFIG_COUNT"] = "2"
            env["GIT_CONFIG_KEY_1"] = "http.https://github.com/.extraheader"
            env["GIT_CONFIG_VALUE_1"] = f"Authorization: Basic {identifiants}"
        return env

    def _git(self, *args: str, verifier: bool = True) -> subprocess.CompletedProcess:
        resultat = subprocess.run(
            ["git", *args],
            cwd=self.dossier,
            env=self._env(),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if verifier and resultat.returncode != 0:
            # Ne jamais journaliser l'environnement (il contient le jeton).
            raise RuntimeError(f"git {args[0]} : {resultat.stderr.strip()[:300]}")
        return resultat

    # --- démarrage -----------------------------------------------------------
    def demarrer(self, dossier: Path) -> None:
        if not self._url:
            journal.info("GITHUB_REPO absent : espace de travail local uniquement.")
            return
        import workspace

        self.dossier = dossier
        self.dossier_git = workspace.dossier_git()
        with self.verrou:
            if (self.dossier_git / "HEAD").is_file():
                self._git("remote", "set-url", "origin", self._url)
            else:
                self._git("init", "-q", "-b", self._branche)
                self._git("remote", "add", "origin", self._url)
            self._git("fetch", "-q", "origin")
            distante = self._git("rev-parse", "--verify", "-q", f"origin/{self._branche}", verifier=False)
            if distante.returncode == 0:
                # Le contenu du dépôt fait foi au démarrage.
                self._git("checkout", "-q", "-B", self._branche, f"origin/{self._branche}", "--force")
                self._git("clean", "-q", "-fd")
            ignore = dossier / ".gitignore"
            if not ignore.exists():
                ignore.write_text(".tmp-*\n", encoding="utf-8")
                self._sale = True
                self._messages.append("Initialise l'espace de travail")
        self.actif = True
        threading.Thread(target=self._boucle, name="depot-git", daemon=True).start()
        atexit.register(self.arreter)
        journal.info("Espace de travail synchronisé avec %s (%s).", self._url.split("@")[-1], self._branche)

    # --- signalement des écritures -------------------------------------------
    def signaler(self, message: str) -> None:
        if not self.actif:
            return
        with self.verrou:
            self._sale = True
            self._messages.append(message)
        self._evenement.set()

    # --- boucle de synchronisation --------------------------------------------
    def _boucle(self) -> None:
        while not self._arret:
            reveille = self._evenement.wait(INTERVALLE_RECUPERATION)
            if reveille:
                time.sleep(DELAI_REGROUPEMENT)  # regroupe les écritures rapprochées
            self._evenement.clear()
            try:
                self.synchroniser()
                self.derniere_erreur = None
            except Exception as erreur:  # on réessaiera au prochain tour
                self.derniere_erreur = str(erreur)
                journal.warning("Synchronisation GitHub échouée : %s", erreur)
                if self._sale:
                    self._evenement.set()
                time.sleep(10)

    def synchroniser(self) -> None:
        if not self.actif:
            return
        with self._verrou_sync:
            self._synchroniser()

    def _synchroniser(self) -> None:
        with self.verrou:
            if self._sale:
                self._git("add", "-A")
                if self._git("diff", "--cached", "--quiet", verifier=False).returncode != 0:
                    messages = list(dict.fromkeys(self._messages))
                    titre = messages[0] if len(messages) == 1 else f"{len(messages)} modifications des IA"
                    corps = "\n".join(f"- {m}" for m in messages[:50]) if len(messages) > 1 else ""
                    self._git("commit", "-q", "-m", titre, *(["-m", corps] if corps else []))
                self._sale = False
                self._messages.clear()

        self._git("fetch", "-q", "origin")  # réseau : hors verrou
        with self.verrou:
            distante = self._git("rev-parse", "--verify", "-q", f"origin/{self._branche}", verifier=False)
            if distante.returncode == 0:
                rebase = self._git("rebase", "-q", f"origin/{self._branche}", verifier=False)
                if rebase.returncode != 0:
                    # Conflit : on garde la version des IA pour les fichiers en conflit.
                    self._git("rebase", "--abort", verifier=False)
                    self._git("merge", "-q", "-X", "ours", "--no-edit", f"origin/{self._branche}")
            en_avance = self._git("rev-list", "--count", f"origin/{self._branche}..HEAD", verifier=False)
            a_pousser = distante.returncode != 0 or (en_avance.stdout.strip() not in ("", "0"))
            a_des_commits = self._git("rev-parse", "--verify", "-q", "HEAD", verifier=False).returncode == 0

        if a_pousser and a_des_commits:
            self._git("push", "-q", "origin", f"HEAD:{self._branche}")

    def arreter(self) -> None:
        """Dernière sauvegarde avant l'arrêt du serveur (redéploiement Render)."""
        if not self.actif or self._arret:
            return
        self._arret = True
        self._evenement.set()
        try:
            self.synchroniser()
        except Exception as erreur:
            journal.warning("Sauvegarde finale échouée : %s", erreur)


depot = Depot()
