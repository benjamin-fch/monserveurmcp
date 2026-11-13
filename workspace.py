"""Espace de travail partagé : opérations de fichiers confinées dans un seul dossier.

Toutes les fonctions prennent des chemins RELATIFS à la racine de l'espace de
travail (variable d'environnement WORKSPACE_DIR). Tout chemin qui en sortirait
(``..``, chemin absolu, lien symbolique) est refusé.
"""

import io
import os
import tempfile
import zipfile
from functools import lru_cache
from pathlib import Path

MAX_LECTURE_OCTETS = 5_000_000
MAX_ECRITURE_OCTETS = 2_000_000
MAX_ENTREES_LISTE = 1000
MAX_RESULTATS_RECHERCHE = 200
MAX_ZIP_OCTETS = 100_000_000


class WorkspaceError(Exception):
    """Erreur d'utilisation (chemin invalide, fichier introuvable, quota...)."""


@lru_cache(maxsize=1)
def racine() -> Path:
    dossier = os.environ.get("WORKSPACE_DIR") or str(Path(__file__).parent / "workspace")
    chemin = Path(dossier).expanduser().resolve()
    chemin.mkdir(parents=True, exist_ok=True)
    return chemin


def quota_octets() -> int:
    return int(os.environ.get("WORKSPACE_MAX_BYTES", "200000000"))


def chemin_sur(relatif: str) -> Path:
    """Résout un chemin relatif en s'assurant qu'il reste dans la racine."""
    base = racine()
    propre = (relatif or "").replace("\\", "/").strip().lstrip("/")
    cible = (base / propre).resolve()
    if cible != base and base not in cible.parents:
        raise WorkspaceError("Chemin refusé : il sort de l'espace de travail.")
    return cible


def _relatif(chemin: Path) -> str:
    rel = chemin.relative_to(racine()).as_posix()
    return "" if rel == "." else rel


def _taille_totale() -> int:
    total = 0
    for dossier, _, fichiers in os.walk(racine()):
        for nom in fichiers:
            p = Path(dossier) / nom
            if not p.is_symlink():
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
    return total


def _est_binaire(octets: bytes) -> bool:
    return b"\x00" in octets[:8192]


def lister(chemin: str = "", recursif: bool = False) -> dict:
    cible = chemin_sur(chemin)
    if not cible.exists():
        raise WorkspaceError("Dossier introuvable.")
    if not cible.is_dir():
        raise WorkspaceError("Ce chemin est un fichier, pas un dossier.")

    iterateur = cible.rglob("*") if recursif else cible.iterdir()
    entrees = []
    tronque = False
    for p in sorted(iterateur):
        if p.is_symlink():
            continue
        if len(entrees) >= MAX_ENTREES_LISTE:
            tronque = True
            break
        est_dossier = p.is_dir()
        entrees.append(
            {
                "chemin": _relatif(p),
                "type": "dossier" if est_dossier else "fichier",
                "taille": None if est_dossier else p.stat().st_size,
            }
        )
    return {"dossier": _relatif(cible), "entrees": entrees, "tronque": tronque}


def lire(chemin: str, debut: int = 0, longueur: int = 200_000) -> dict:
    cible = chemin_sur(chemin)
    if not cible.is_file():
        raise WorkspaceError("Fichier introuvable.")
    if cible.stat().st_size > MAX_LECTURE_OCTETS:
        raise WorkspaceError("Fichier trop volumineux pour être lu (> 5 Mo).")
    octets = cible.read_bytes()
    if _est_binaire(octets):
        raise WorkspaceError("Fichier binaire : lecture texte impossible.")
    texte = octets.decode("utf-8", errors="replace")
    debut = max(0, debut)
    longueur = max(1, min(longueur, 500_000))
    extrait = texte[debut : debut + longueur]
    return {
        "chemin": _relatif(cible),
        "contenu": extrait,
        "caracteres_total": len(texte),
        "tronque": debut + longueur < len(texte),
    }


def _ecrire_atomique(cible: Path, octets: bytes) -> None:
    cible.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=cible.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(octets)
        os.replace(tmp, cible)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _verifier_ecriture(octets: bytes, ajout: int) -> None:
    if len(octets) > MAX_ECRITURE_OCTETS:
        raise WorkspaceError("Contenu trop volumineux (> 2 Mo par écriture).")
    if _taille_totale() + ajout > quota_octets():
        raise WorkspaceError("Quota de l'espace de travail dépassé.")


def ecrire(chemin: str, contenu: str, ecraser: bool = True) -> dict:
    cible = chemin_sur(chemin)
    if cible == racine() or cible.is_dir():
        raise WorkspaceError("Ce chemin est un dossier.")
    if cible.exists() and not ecraser:
        raise WorkspaceError("Le fichier existe déjà (ecraser=false).")
    octets = contenu.encode("utf-8")
    ancien = cible.stat().st_size if cible.exists() else 0
    _verifier_ecriture(octets, max(0, len(octets) - ancien))
    _ecrire_atomique(cible, octets)
    return {"chemin": _relatif(cible), "octets": len(octets)}


def ajouter(chemin: str, contenu: str) -> dict:
    cible = chemin_sur(chemin)
    if cible == racine() or cible.is_dir():
        raise WorkspaceError("Ce chemin est un dossier.")
    ajout = contenu.encode("utf-8")
    _verifier_ecriture(ajout, len(ajout))
    existant = cible.read_bytes() if cible.exists() else b""
    if len(existant) + len(ajout) > MAX_LECTURE_OCTETS:
        raise WorkspaceError("Le fichier deviendrait trop volumineux (> 5 Mo).")
    _ecrire_atomique(cible, existant + ajout)
    return {"chemin": _relatif(cible), "octets": len(existant) + len(ajout)}


def creer_dossier(chemin: str) -> dict:
    cible = chemin_sur(chemin)
    if cible.exists() and not cible.is_dir():
        raise WorkspaceError("Un fichier existe déjà à cet emplacement.")
    cible.mkdir(parents=True, exist_ok=True)
    return {"chemin": _relatif(cible)}


def supprimer(chemin: str) -> dict:
    cible = chemin_sur(chemin)
    if cible == racine():
        raise WorkspaceError("Impossible de supprimer la racine.")
    if not cible.exists():
        raise WorkspaceError("Chemin introuvable.")
    if cible.is_dir():
        try:
            cible.rmdir()
        except OSError:
            raise WorkspaceError("Dossier non vide : supprime d'abord son contenu.")
    else:
        cible.unlink()
    return {"supprime": _relatif(cible)}


def deplacer(source: str, destination: str) -> dict:
    src = chemin_sur(source)
    dst = chemin_sur(destination)
    if src == racine() or dst == racine():
        raise WorkspaceError("Impossible de déplacer la racine.")
    if not src.exists():
        raise WorkspaceError("Source introuvable.")
    if dst.exists():
        raise WorkspaceError("La destination existe déjà.")
    dst.parent.mkdir(parents=True, exist_ok=True)
    os.replace(src, dst)
    return {"de": _relatif(src), "vers": _relatif(dst)}


def chercher(texte: str, chemin: str = "") -> dict:
    if not texte:
        raise WorkspaceError("Le texte recherché est vide.")
    cible = chemin_sur(chemin)
    if not cible.exists():
        raise WorkspaceError("Chemin introuvable.")
    fichiers = [cible] if cible.is_file() else sorted(cible.rglob("*"))
    aiguille = texte.lower()
    resultats = []
    tronque = False
    for p in fichiers:
        if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_LECTURE_OCTETS:
            continue
        octets = p.read_bytes()
        if _est_binaire(octets):
            continue
        for numero, ligne in enumerate(octets.decode("utf-8", errors="replace").splitlines(), 1):
            if aiguille in ligne.lower():
                if len(resultats) >= MAX_RESULTATS_RECHERCHE:
                    tronque = True
                    break
                resultats.append({"chemin": _relatif(p), "ligne": numero, "texte": ligne[:300]})
        if tronque:
            break
    return {"resultats": resultats, "tronque": tronque}


def archive_zip() -> bytes:
    """Archive de tout l'espace de travail (pour la synchronisation vers VS Code)."""
    tampon = io.BytesIO()
    total = 0
    with zipfile.ZipFile(tampon, "w", zipfile.ZIP_DEFLATED) as z:
        for dossier, _, fichiers in os.walk(racine()):
            for nom in sorted(fichiers):
                p = Path(dossier) / nom
                if p.is_symlink() or nom.startswith(".tmp-"):
                    continue
                total += p.stat().st_size
                if total > MAX_ZIP_OCTETS:
                    raise WorkspaceError("Espace de travail trop gros pour l'archive (> 100 Mo).")
                z.write(p, _relatif(p))
    return tampon.getvalue()
