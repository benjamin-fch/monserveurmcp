"""Bac à sable d'analyse de liens suspects.

Le serveur va voir le site À LA PLACE de l'utilisateur : rien n'est ouvert sur
son téléphone. La récupération est « passive » :

- la page est téléchargée comme du simple texte, son JavaScript n'est JAMAIS
  exécuté, aucun fichier n'est ouvert ni installé, aucun cookie n'est envoyé ;
- les adresses internes (localhost, réseau privé, métadonnées du cloud…) sont
  refusées à chaque étape, redirections comprises (protection SSRF) ;
- taille, durée et nombre de redirections sont limités.

En option (clés d'API dans les variables d'environnement), trois services
externes complètent l'analyse :

- GOOGLE_SAFE_BROWSING_KEY : listes noires de Google (gratuit, usage non commercial) ;
- VIRUSTOTAL_API_KEY       : avis de ~90 antivirus (gratuit, 4 requêtes/min) ;
- URLSCAN_API_KEY          : un vrai navigateur ouvre le site dans le bac à sable
                             d'urlscan.io et en fait une capture d'écran.

Utilisation en ligne de commande (depuis la racine du dépôt) :
    python -m verificateur_liens.analyse_lien "https://lien-suspect"
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser


# --- Réglages -------------------------------------------------------------

PORTS_AUTORISES = {80, 443, 8080, 8443}
MAX_REDIRECTIONS = 8
MAX_OCTETS = 1_500_000          # taille maximale lue par page
DELAI_RESEAU = 8                # secondes par opération réseau
BUDGET_PAGE = 20                # secondes pour toute la chaîne de redirections
BUDGET_TOTAL = 50               # secondes pour toute l'analyse
LONGUEUR_MAX_URL = 2048
DUREE_CACHE = 600               # un même lien n'est pas réanalysé pendant 10 min

AGENTS = {
    "mobile": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
    ),
    "ordinateur": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
}

SEUIL_DANGEREUX = 50
SEUIL_SUSPECT = 20


class LienInvalide(ValueError):
    """Le texte fourni n'est pas un lien web analysable."""


class LienRefuse(ValueError):
    """Le lien vise une adresse interdite (réseau interne, port exotique…)."""


class ErreurRecuperation(Exception):
    """Le site n'a pas pu être récupéré (introuvable, injoignable, trop lent…)."""


# --- Données de référence -------------------------------------------------

# Marques souvent imitées. « mots » : ce qu'on cherche dans le nom de domaine ;
# « sous_chaine » : chercher aussi le mot collé à d'autres (securepaypal.com) ;
# « textes » : ce qui trahit la marque dans le titre de la page.
MARQUES = [
    {"nom": "Ameli (Assurance Maladie)", "mots": ["ameli"], "sous_chaine": False,
     "textes": ["ameli", "assurance maladie", "carte vitale"], "officiels": ["ameli.fr"]},
    {"nom": "Impots.gouv", "mots": ["impots", "impot", "dgfip"], "sous_chaine": True,
     "textes": ["impots.gouv", "finances publiques", "dgfip"], "officiels": ["impots.gouv.fr"]},
    {"nom": "ANTAI (amendes)", "mots": ["antai"], "sous_chaine": False,
     "textes": ["antai", "traitement automatise des infractions"], "officiels": ["antai.gouv.fr"]},
    {"nom": "ANTS", "mots": ["ants"], "sous_chaine": False,
     "textes": ["ants.gouv", "agence nationale des titres securises"], "officiels": ["ants.gouv.fr"]},
    {"nom": "CAF", "mots": ["caf"], "sous_chaine": False,
     "textes": ["caf.fr", "allocations familiales"], "officiels": ["caf.fr"]},
    {"nom": "Crit'Air", "mots": ["critair", "crit-air"], "sous_chaine": True,
     "textes": ["crit'air", "critair", "certificat qualite de l'air"],
     "officiels": ["certificat-air.gouv.fr"]},
    {"nom": "FranceConnect", "mots": ["franceconnect"], "sous_chaine": True,
     "textes": ["franceconnect"], "officiels": ["franceconnect.gouv.fr"]},
    {"nom": "Mon Compte Formation (CPF)", "mots": ["moncompteformation", "cpf"], "sous_chaine": False,
     "textes": ["mon compte formation", "moncompteformation"],
     "officiels": ["moncompteformation.gouv.fr"]},
    {"nom": "Service-Public.fr", "mots": ["servicepublic", "service-public"], "sous_chaine": True,
     "textes": ["service-public.fr"], "officiels": ["service-public.fr", "service-public.gouv.fr"]},
    {"nom": "La Poste", "mots": ["laposte", "la-poste"], "sous_chaine": True,
     "textes": ["la poste", "laposte"], "officiels": ["laposte.fr", "laposte.net", "lapostegroupe.com"]},
    {"nom": "Colissimo", "mots": ["colissimo"], "sous_chaine": True,
     "textes": ["colissimo"], "officiels": ["colissimo.fr", "laposte.fr"]},
    {"nom": "Chronopost", "mots": ["chronopost"], "sous_chaine": True,
     "textes": ["chronopost"], "officiels": ["chronopost.fr", "chronopost.com"]},
    {"nom": "Mondial Relay", "mots": ["mondialrelay", "mondial-relay"], "sous_chaine": True,
     "textes": ["mondial relay"], "officiels": ["mondialrelay.fr", "mondialrelay.com"]},
    {"nom": "DHL", "mots": ["dhl"], "sous_chaine": False,
     "textes": ["dhl"], "officiels": ["dhl.com", "dhl.fr", "dhl.de"]},
    {"nom": "UPS", "mots": ["ups"], "sous_chaine": False,
     "textes": ["ups.com", "united parcel service"], "officiels": ["ups.com"]},
    {"nom": "FedEx", "mots": ["fedex"], "sous_chaine": True,
     "textes": ["fedex"], "officiels": ["fedex.com"]},
    {"nom": "DPD", "mots": ["dpd"], "sous_chaine": False,
     "textes": ["dpd"], "officiels": ["dpd.fr", "dpd.com"]},
    {"nom": "Vinted", "mots": ["vinted"], "sous_chaine": True,
     "textes": ["vinted"], "officiels": ["vinted.fr", "vinted.com"]},
    {"nom": "Leboncoin", "mots": ["leboncoin", "lebon-coin"], "sous_chaine": True,
     "textes": ["leboncoin"], "officiels": ["leboncoin.fr"]},
    {"nom": "Amazon", "mots": ["amazon"], "sous_chaine": True,
     "textes": ["amazon"],
     "officiels": ["amazon.fr", "amazon.com", "amazon.de", "amazon.co.uk", "amazon.es",
                   "amazon.it", "amazon.com.be", "amazon.ca", "amazonaws.com", "media-amazon.com"]},
    {"nom": "PayPal", "mots": ["paypal"], "sous_chaine": True,
     "textes": ["paypal"], "officiels": ["paypal.com", "paypal.fr", "paypal.me", "paypalobjects.com"]},
    {"nom": "Apple / iCloud", "mots": ["apple", "icloud", "itunes", "appleid"], "sous_chaine": False,
     "textes": ["apple id", "identifiant apple", "icloud"],
     "officiels": ["apple.com", "icloud.com", "itunes.com", "apple.fr"]},
    {"nom": "Microsoft / Outlook", "mots": ["microsoft", "outlook", "hotmail", "office365"],
     "sous_chaine": True, "textes": ["microsoft", "outlook", "office 365", "hotmail"],
     "officiels": ["microsoft.com", "microsoftonline.com", "live.com", "outlook.com",
                   "office.com", "office365.com", "hotmail.com", "msn.com", "hotmail.fr"]},
    {"nom": "Google / Gmail", "mots": ["google", "gmail"], "sous_chaine": True,
     "textes": ["google", "gmail"],
     "officiels": ["google.com", "google.fr", "gmail.com", "youtube.com", "googleapis.com",
                   "googleusercontent.com", "gstatic.com", "google.co.uk", "google.de"]},
    {"nom": "Facebook / Meta", "mots": ["facebook"], "sous_chaine": True,
     "textes": ["facebook"], "officiels": ["facebook.com", "fb.com", "meta.com", "fbcdn.net"]},
    {"nom": "Instagram", "mots": ["instagram"], "sous_chaine": True,
     "textes": ["instagram"], "officiels": ["instagram.com", "cdninstagram.com"]},
    {"nom": "WhatsApp", "mots": ["whatsapp"], "sous_chaine": True,
     "textes": ["whatsapp"], "officiels": ["whatsapp.com", "whatsapp.net", "wa.me"]},
    {"nom": "Netflix", "mots": ["netflix"], "sous_chaine": True,
     "textes": ["netflix"], "officiels": ["netflix.com", "nflxext.com"]},
    {"nom": "Orange", "mots": ["orange"], "sous_chaine": False,
     "textes": ["orange.fr", "espace client orange", "messagerie orange"],
     "officiels": ["orange.fr", "orange.com", "orange-business.com"]},
    {"nom": "SFR", "mots": ["sfr"], "sous_chaine": False,
     "textes": ["sfr"], "officiels": ["sfr.fr"]},
    {"nom": "Bouygues Telecom", "mots": ["bouygues", "bouyguestelecom"], "sous_chaine": True,
     "textes": ["bouygues telecom"], "officiels": ["bouyguestelecom.fr", "bouygues.com"]},
    {"nom": "Crédit Agricole", "mots": ["creditagricole", "credit-agricole"], "sous_chaine": True,
     "textes": ["credit agricole"], "officiels": ["credit-agricole.fr", "credit-agricole.com"]},
    {"nom": "BNP Paribas", "mots": ["bnpparibas", "bnp"], "sous_chaine": False,
     "textes": ["bnp paribas"],
     "officiels": ["bnpparibas", "bnpparibas.com", "bnpparibas.fr", "mabanque.bnpparibas"]},
    {"nom": "Société Générale", "mots": ["societegenerale", "societe-generale"], "sous_chaine": True,
     "textes": ["societe generale"],
     "officiels": ["societegenerale.fr", "societegenerale.com", "sg.fr"]},
    {"nom": "LCL", "mots": ["lcl"], "sous_chaine": False,
     "textes": ["lcl banque", "le credit lyonnais"], "officiels": ["lcl.fr"]},
    {"nom": "La Banque Postale", "mots": ["labanquepostale", "banquepostale"], "sous_chaine": True,
     "textes": ["la banque postale"], "officiels": ["labanquepostale.fr"]},
    {"nom": "Crédit Mutuel", "mots": ["creditmutuel", "credit-mutuel"], "sous_chaine": True,
     "textes": ["credit mutuel"], "officiels": ["creditmutuel.fr", "creditmutuel.com"]},
    {"nom": "Boursorama / BoursoBank", "mots": ["boursorama", "boursobank"], "sous_chaine": True,
     "textes": ["boursorama", "boursobank"], "officiels": ["boursorama.com", "boursobank.com"]},
    {"nom": "Revolut", "mots": ["revolut"], "sous_chaine": True,
     "textes": ["revolut"], "officiels": ["revolut.com", "revolut.me"]},
    {"nom": "Doctolib", "mots": ["doctolib"], "sous_chaine": True,
     "textes": ["doctolib"], "officiels": ["doctolib.fr", "doctolib.de", "doctolib.it"]},
    {"nom": "SNCF", "mots": ["sncf", "sncfconnect", "sncf-connect"], "sous_chaine": False,
     "textes": ["sncf connect", "sncf"], "officiels": ["sncf-connect.com", "sncf.com", "sncf.fr"]},
    {"nom": "EDF", "mots": ["edf"], "sous_chaine": False,
     "textes": ["edf"], "officiels": ["edf.fr", "edf.com"]},
    {"nom": "Engie", "mots": ["engie"], "sous_chaine": False,
     "textes": ["engie"], "officiels": ["engie.fr", "engie.com"]},
    {"nom": "Steam", "mots": ["steamcommunity", "steampowered"], "sous_chaine": True,
     "textes": ["steam community"], "officiels": ["steamcommunity.com", "steampowered.com"]},
    {"nom": "Binance", "mots": ["binance"], "sous_chaine": True,
     "textes": ["binance"], "officiels": ["binance.com"]},
    {"nom": "Coinbase", "mots": ["coinbase"], "sous_chaine": True,
     "textes": ["coinbase"], "officiels": ["coinbase.com"]},
]

# Suffixes à deux niveaux et plateformes d'hébergement où chacun crée son
# sous-domaine (extrait simplifié de la Public Suffix List).
SUFFIXES_MULTIPLES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "com.br", "com.cn", "com.tr", "co.za", "co.in", "com.mx", "com.ar",
    "co.kr", "com.sg", "com.hk", "com.tw", "com.be", "gouv.fr", "asso.fr", "nom.fr",
    "presse.fr", "tm.fr", "com.es", "com.pl", "com.ua", "co.il",
}
PLATEFORMES = {
    "github.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "r2.dev",
    "web.app", "firebaseapp.com", "herokuapp.com", "onrender.com", "glitch.me",
    "wixsite.com", "weebly.com", "blogspot.com", "000webhostapp.com",
    "azurewebsites.net", "cloudfront.net", "appspot.com", "s3.amazonaws.com",
    "storage.googleapis.com", "ngrok-free.app", "ngrok.io", "ngrok.app", "translate.goog",
    "webflow.io", "framer.website", "framer.app", "myshopify.com", "square.site",
    "godaddysites.com", "carrd.co", "replit.app", "repl.co", "surge.sh", "fly.dev",
    "deno.dev", "trycloudflare.com", "ipfs.dweb.link", "ipfs.io", "sites.google.com",
    "forms.gle", "jimdosite.com", "webnode.page", "mystrikingly.com", "hpage.com",
    "teachable.com", "gitbook.io", "notion.site", "typedream.app", "dorik.io",
}
DNS_DYNAMIQUES = {
    "duckdns.org", "ddns.net", "no-ip.org", "no-ip.biz", "hopto.org", "zapto.org",
    "sytes.net", "myftp.org", "serveo.net", "dynu.net", "freeddns.org", "linkpc.net",
}
RACCOURCISSEURS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "ow.ly",
    "shorturl.at", "tiny.cc", "s.id", "t.ly", "rebrand.ly", "buff.ly", "goo.gl",
    "bl.ink", "qrco.de", "urlz.fr", "frama.link", "short.gy", "v.gd", "shorturl.gg",
    "lnkd.in", "x.gd", "u.to", "clck.ru", "tny.im", "bitly.com", "1url.com",
}
TLD_A_RISQUE = {
    "xyz", "top", "click", "link", "shop", "online", "site", "live", "icu", "buzz",
    "cfd", "sbs", "rest", "monster", "tk", "ml", "ga", "cf", "gq", "cyou", "bond",
    "quest", "support", "help", "store", "vip", "lol", "mom", "today", "win", "loan",
    "work", "fit", "pw", "su", "zip", "mov", "info", "life", "world", "cam", "beauty",
    "hair", "makeup", "skin", "autos", "boats", "homes", "motorcycles", "yachts", "pics",
    "best", "fun", "space", "website", "club", "digital", "network", "center",
}
MOTS_URL = [
    "login", "signin", "sign-in", "verify", "verification", "secure", "securite",
    "update", "account", "compte", "confirm", "suivi", "colis", "livraison",
    "remboursement", "amende", "paiement", "payment", "facture", "bloque",
    "suspendu", "debloquer", "identifiant", "connexion", "banking", "wallet",
    "recover", "unlock", "reactivation", "cadeau", "gagnant", "gift", "validation", "reglement", "regularisation", "majoration", "carte-vitale",
]
PHRASES_URGENCE = [
    "compte suspendu", "compte bloque", "compte a ete suspendu", "compte a ete bloque",
    "dernier rappel", "action requise", "sous 24h", "sous 24 heures", "sous 48h",
    "dans les 24h", "dans les 48h", "frais de reexpedition", "frais de livraison",
    "frais de port de", "colis en attente", "colis bloque", "colis n'a pas pu",
    "livraison echouee", "echec de livraison", "votre amende", "majoration",
    "remboursement de", "vous avez gagne", "felicitations", "mettre a jour vos informations",
    "mettre a jour vos coordonnees", "verifier votre identite", "renouveler votre carte vitale",
    "account suspended", "verify your account", "unusual activity", "within 24 hours",
    "your package", "confirm your identity", "payment failed", "paiement refuse",
    "paiement a echoue", "derniere relance", "avant poursuites", "huissier",
]
EXTENSIONS_DANGEREUSES = {
    "apk": 35, "xapk": 35, "apks": 35, "ipa": 35, "mobileconfig": 40, "exe": 35,
    "msi": 35, "scr": 40, "bat": 35, "cmd": 35, "vbs": 35, "ps1": 35, "hta": 40,
    "jar": 30, "dmg": 30, "pkg": 30, "lnk": 35, "iso": 25, "img": 20,
    "zip": 10, "rar": 12, "7z": 12,
}
TYPES_DANGEREUX = {
    "application/vnd.android.package-archive": ("une application Android (APK)", 40),
    "application/x-apple-aspen-config": ("un profil de configuration iPhone", 45),
    "application/x-msdownload": ("un programme Windows", 40),
    "application/x-msi": ("un installeur Windows", 40),
    "application/x-dosexec": ("un programme Windows", 40),
    "application/java-archive": ("une archive Java", 30),
    "application/x-apple-diskimage": ("une image disque macOS", 30),
}
MENACES_GOOGLE = {
    "MALWARE": "logiciel malveillant",
    "SOCIAL_ENGINEERING": "hameçonnage (phishing) / arnaque",
    "UNWANTED_SOFTWARE": "logiciel indésirable",
    "POTENTIALLY_HARMFUL_APPLICATION": "application dangereuse",
}

# Lettres d'autres alphabets qui ressemblent à des lettres latines (homographes).
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ӏ": "l", "ɡ": "g", "ν": "v", "ο": "o",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "ϲ": "c", "ԛ": "q", "ԝ": "w", "ɩ": "l", "ı": "i", "ℓ": "l", "ⅼ": "l", "ᴏ": "o",
    "ɑ": "a", "ʏ": "y", "ꮪ": "s", "ꭰ": "d",
})
CHIFFRES_L = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})
CHIFFRES_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})
# Mots courants à une lettre d'une marque : ce ne sont pas des imitations.
FAUX_SOSIES = {"finance", "finances", "oranges", "orangea", "revolt", "revolte", "amazone",
               "amazona", "vintage", "goggles", "boogle", "doodle", "colisimo"}
SCHEMAS_DANGEREUX = {
    "itms-services": "Ce lien sert à installer une application iPhone HORS App Store : ne l'ouvre surtout pas.",
    "intent": "Ce lien ouvre directement une application Android : ne l'ouvre pas si tu ne connais pas l'expéditeur.",
    "market": "Lien vers une application Android : vérifie plutôt l'appli en la cherchant toi-même dans le Play Store.",
    "javascript": "Ce n'est pas un lien web mais du code JavaScript : ne l'ouvre pas.",
    "data": "Ce « lien » contient directement une page cachée (data:) : technique de phishing, ne l'ouvre pas.",
    "file": "Lien vers un fichier local : non analysable.",
    "vbscript": "Ce n'est pas un lien web mais du code : ne l'ouvre pas.",
    "blob": "Lien interne au navigateur : non analysable.",
}


# --- Petits outils --------------------------------------------------------


def _sans_accents(texte: str) -> str:
    decompose = unicodedata.normalize("NFKD", texte)
    return "".join(c for c in decompose if not unicodedata.combining(c)).lower()


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    precedente = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        courante = [i]
        for j, cb in enumerate(b, 1):
            courante.append(min(
                precedente[j] + 1, courante[j - 1] + 1, precedente[j - 1] + (ca != cb)
            ))
        precedente = courante
    return precedente[-1]


def _idna(hote: str) -> str:
    """Nom de domaine en ASCII (punycode) pour le DNS et le TLS."""
    try:
        return hote.encode("idna").decode("ascii")
    except UnicodeError:
        try:
            return ".".join(
                "xn--" + p.encode("punycode").decode("ascii") if not p.isascii() else p
                for p in hote.split(".")
            )
        except UnicodeError as erreur:
            raise LienInvalide(f"Nom de domaine illisible : {hote}") from erreur


def _unicode(hote: str) -> str:
    """Nom de domaine tel qu'il s'affiche (punycode décodé)."""
    try:
        return hote.encode("ascii").decode("idna")
    except UnicodeError:
        return hote


def _est_ip(hote: str) -> bool:
    try:
        ipaddress.ip_address(hote)
        return True
    except ValueError:
        # Formes déguisées : 2130706433, 0x7f000001, 0177.0.0.1…
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", hote))


def domaine_enregistre(hote: str) -> str:
    """Partie du nom achetée par le propriétaire (ex. a.b.exemple.co.uk -> exemple.co.uk)."""
    hote = hote.lower().rstrip(".")
    if _est_ip(hote):
        return hote
    morceaux = hote.split(".")
    for taille in (3, 2):
        if len(morceaux) > taille and ".".join(morceaux[-taille:]) in (
            SUFFIXES_MULTIPLES | PLATEFORMES | DNS_DYNAMIQUES
        ):
            return ".".join(morceaux[-(taille + 1):])
    return ".".join(morceaux[-2:])


def _plateforme(hote: str, liste: set[str]) -> str | None:
    for suffixe in liste:
        if hote == suffixe or hote.endswith("." + suffixe):
            return suffixe
    return None


def _est_officiel(hote: str, marque: dict) -> bool:
    return any(hote == o or hote.endswith("." + o) for o in marque["officiels"])


def _domaine_de(url: str) -> str:
    """Domaine enregistré (en ASCII) d'une URL."""
    hote = (urllib.parse.urlsplit(url).hostname or "").rstrip(".")
    if not hote:
        return ""
    try:
        return domaine_enregistre(hote if _est_ip(hote) else _idna(hote))
    except LienInvalide:
        return hote


def _mentionne(texte_norm: str, terme: str) -> bool:
    """Le terme apparaît-il (en mot entier pour les sigles courts) ?"""
    if len(terme) < 5:
        return re.search(rf"(?<![a-z0-9]){re.escape(terme)}(?![a-z0-9])", texte_norm) is not None
    return terme in texte_norm


def normaliser_url(brut: str) -> str:
    """Nettoie un lien collé (espaces, liens « désamorcés » hxxp/[.]) et le valide."""
    if not isinstance(brut, str) or not brut.strip():
        raise LienInvalide("Aucun lien fourni.")
    url = brut.strip().strip("<>\"'`").strip()
    url = re.sub(r"^hxxp", "http", url, flags=re.I)
    url = url.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[dot]", ".")
    if len(url) > LONGUEUR_MAX_URL:
        raise LienInvalide("Lien trop long.")
    if re.search(r"[\x00-\x1f\x7f\s]", url):
        raise LienInvalide("Le lien contient des espaces ou des caractères invisibles.")
    schema = re.match(r"^([a-z][a-z0-9+.\-]*):(?!\d)", url, re.I)
    if schema and schema.group(1).lower() not in ("http", "https"):
        nom = schema.group(1).lower()
        raise LienInvalide(SCHEMAS_DANGEREUX.get(
            nom, f"Seuls les liens web (http/https) sont analysables (reçu : « {nom}: »)."))
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url.lstrip("/")
    morceaux = urllib.parse.urlsplit(url)
    if not morceaux.hostname:
        raise LienInvalide("Lien sans nom de site.")
    return url


# --- Signaux --------------------------------------------------------------


@dataclass
class Rapport:
    signaux: list[dict] = field(default_factory=list)
    rassurants: list[dict] = field(default_factory=list)
    _vus: set[str] = field(default_factory=set)

    def alerte(self, points: int, code: str, detail: str) -> None:
        if code in self._vus:
            return
        self._vus.add(code)
        self.signaux.append({"points": points, "code": code, "detail": detail})

    def rassure(self, points: int, code: str, detail: str) -> None:
        if code in self._vus:
            return
        self._vus.add(code)
        self.rassurants.append({"points": points, "code": code, "detail": detail})

    def score(self) -> int:
        brut = sum(s["points"] for s in self.signaux) - sum(r["points"] for r in self.rassurants)
        return max(0, min(100, brut))


def _squelettes(mot: str) -> set[str]:
    base = _sans_accents(mot.translate(CONFUSABLES))
    variantes = {base, base.translate(CHIFFRES_L), base.translate(CHIFFRES_I)}
    return {v.replace("rn", "m").replace("vv", "w") for v in variantes} | variantes


def analyser_url(url: str, rapport: Rapport, etiquette: str = "") -> dict:
    """Heuristiques sur l'adresse elle-même (sans contacter le site)."""
    suffixe = f" ({etiquette})" if etiquette else ""
    morceaux = urllib.parse.urlsplit(url)
    hote_brut = (morceaux.hostname or "").rstrip(".")
    hote = _unicode(hote_brut.lower())
    hote_ascii = _idna(hote) if not _est_ip(hote) else hote
    domaine = domaine_enregistre(hote_ascii)
    domaine_affiche = _unicode(domaine)
    sans_www = hote[4:] if hote.startswith("www.") else hote
    chemin = _sans_accents(urllib.parse.unquote(
        (morceaux.path or "") + "?" + (morceaux.query or "") + "#" + (morceaux.fragment or "")
    ))
    infos = {"hote": hote, "domaine": domaine_affiche, "domaine_ascii": domaine, "marque_officielle": None}

    if morceaux.scheme.lower() == "http":
        rapport.alerte(15, "http" + etiquette,
                       f"Connexion non chiffrée (http) : tout ce qui est saisi peut être intercepté{suffixe}.")
    if morceaux.username or morceaux.password or "@" in (morceaux.netloc or ""):
        rapport.alerte(35, "arobase" + etiquette,
                       "Le lien contient un « @ » avant le nom du site : piège classique pour "
                       f"afficher un faux nom de site devant le vrai{suffixe}.")
    if _est_ip(hote):
        rapport.alerte(30, "ip" + etiquette,
                       f"Le lien pointe vers une adresse IP brute au lieu d'un nom de site{suffixe}.")
        return infos
    if morceaux.port and morceaux.port not in (80, 443):
        rapport.alerte(10, "port" + etiquette, f"Port inhabituel ({morceaux.port}){suffixe}.")
    if len(url) > 180:
        rapport.alerte(5, "long" + etiquette, f"Lien anormalement long ({len(url)} caractères){suffixe}.")

    tld = hote_ascii.rsplit(".", 1)[-1]
    if tld in TLD_A_RISQUE:
        rapport.alerte(12, "tld" + etiquette,
                       f"Extension « .{tld} » : très bon marché, très utilisée par les arnaques{suffixe}.")
    if hote_ascii != hote_brut.lower() or "xn--" in hote_ascii:
        rapport.alerte(20, "idn" + etiquette,
                       f"Le nom du site contient des caractères spéciaux ou étrangers ({hote} = "
                       f"{hote_ascii}) : peut imiter visuellement un vrai site{suffixe}.")
    if hote_ascii.count(".") >= 4:
        rapport.alerte(8, "sousdomaines" + etiquette,
                       f"Beaucoup de sous-domaines ({hote}) : souvent utilisé pour cacher le vrai site{suffixe}.")
    if domaine_affiche.split(".")[0].count("-") >= 3:
        rapport.alerte(8, "tirets" + etiquette, f"Nom de domaine à rallonge avec des tirets ({domaine_affiche}){suffixe}.")

    plateforme = _plateforme(hote_ascii, PLATEFORMES)
    if plateforme:
        rapport.alerte(12, "plateforme" + etiquette,
                       f"Site hébergé sur une plateforme gratuite ({plateforme}) où n'importe qui "
                       f"peut créer une page en une minute{suffixe}.")
    dyn = _plateforme(hote_ascii, DNS_DYNAMIQUES)
    if dyn:
        rapport.alerte(15, "dyndns" + etiquette, f"Adresse dynamique gratuite ({dyn}), typique des sites jetables{suffixe}.")
    if _plateforme(hote_ascii, RACCOURCISSEURS):
        rapport.alerte(5, "raccourci" + etiquette,
                       "Lien raccourci : la vraie destination est cachée (elle est suivie ci-dessous).")

    # Faux site « gouv »
    if "gouv" in hote_ascii and not (hote_ascii.endswith(".gouv.fr") or hote_ascii == "gouv.fr"):
        rapport.alerte(40, "fauxgouv" + etiquette,
                       f"Le nom contient « gouv » mais ce n'est PAS un site en .gouv.fr ({hote}){suffixe}.")

    # Marques : officielles, imitées dans le nom, ou fautes de frappe volontaires
    compact = re.sub(r"[^a-z0-9]", "", _sans_accents(sans_www))
    jetons = [j for j in re.split(r"[^a-z0-9]+", _sans_accents(sans_www)) if j]
    # Même nom une fois les lettres étrangères « sosies » remplacées (а cyrillique -> a…)
    squelette_hote = _sans_accents(sans_www.translate(CONFUSABLES))
    a_des_sosies = squelette_hote != _sans_accents(sans_www)
    jetons_squelette = [j for j in re.split(r"[^a-z0-9]+", squelette_hote) if j]
    compact_squelette = re.sub(r"[^a-z0-9]", "", squelette_hote)
    etiquette_principale = domaine.split(".")[0]
    jetons_domaine = [j for j in re.split(
        r"[^a-z0-9]+", _sans_accents(_unicode(etiquette_principale).translate(CONFUSABLES))) if j]
    for marque in MARQUES:
        if _est_officiel(hote_ascii, marque):
            # Sur une plateforme d'hébergement (storage.googleapis.com…), n'importe qui publie : pas officiel.
            if not plateforme:
                infos["marque_officielle"] = marque["nom"]
            continue
        for mot in marque["mots"]:
            mot_compact = mot.replace("-", "")
            if a_des_sosies and (mot in jetons_squelette or mot_compact in jetons_squelette or (
                    marque["sous_chaine"] and len(mot_compact) >= 5 and mot_compact in compact_squelette)):
                rapport.alerte(50, "homographe" + etiquette,
                               f"« {hote} » imite {marque['nom']} avec des lettres d'un autre alphabet "
                               f"qui ressemblent aux nôtres (adresse réelle : {hote_ascii}){suffixe}.")
                infos.setdefault("marque_imitee", marque["nom"])
                break
            dans_nom = (mot in jetons or mot_compact in jetons
                        or (marque["sous_chaine"] and len(mot_compact) >= 5 and mot_compact in compact))
            if dans_nom:
                rapport.alerte(35, "marque_hote" + etiquette,
                               f"Le nom du site contient « {mot} » mais ce n'est pas un site officiel de "
                               f"{marque['nom']} ({domaine_affiche}){suffixe}.")
                infos.setdefault("marque_imitee", marque["nom"])
                break
            if len(mot_compact) < 5:
                continue
            for jeton in jetons_domaine + [re.sub(r"[^a-z0-9]", "", etiquette_principale)]:
                if not jeton or jeton == mot_compact or jeton in FAUX_SOSIES:
                    continue
                squelettes = _squelettes(jeton)
                homographe = (mot_compact in squelettes) or (
                    marque["sous_chaine"] and any(mot_compact in s for s in squelettes))
                distance = _levenshtein(jeton, mot_compact)
                proche = len(mot_compact) >= 6 and distance <= (1 if len(mot_compact) < 9 else 2) \
                    and abs(len(jeton) - len(mot_compact)) <= 2
                if homographe or proche:
                    rapport.alerte(45, "typo" + etiquette,
                                   f"« {domaine_affiche} » ressemble à {marque['nom']} avec une lettre "
                                   f"changée : faute de frappe volontaire pour tromper{suffixe}.")
                    infos.setdefault("marque_imitee", marque["nom"])
                    break
        if infos.get("marque_imitee") == marque["nom"]:
            continue
        if any(m.replace("-", "") in re.sub(r"[^a-z0-9]", "", chemin) for m in marque["mots"]
               if len(m.replace("-", "")) >= 5):
            rapport.alerte(12, "marque_chemin" + etiquette,
                           f"L'adresse mentionne {marque['nom']} dans sa partie après le nom du site, "
                           f"alors que le site ({domaine_affiche}) n'est pas {marque['nom']}{suffixe}.")

    mots_trouves = [m for m in MOTS_URL if m in chemin or m in _sans_accents(sans_www)]
    if mots_trouves and not infos["marque_officielle"]:
        rapport.alerte(min(18, 6 * len(mots_trouves)), "motsurl" + etiquette,
                       f"Mots typiques des arnaques dans le lien : {', '.join(mots_trouves[:5])}{suffixe}.")

    # Une autre adresse cachée dans le lien (…?url=https://autre-site)
    if not etiquette:
        requete = urllib.parse.unquote(urllib.parse.unquote(morceaux.query or ""))
        cachee = re.search(r"https?://[^\s&\"'<>]+", requete)
        if cachee and _domaine_de(cachee.group(0)) not in ("", domaine):
            infos["adresse_cachee"] = cachee.group(0)
            rapport.alerte(10, "cachee", f"Le lien contient une autre adresse cachée "
                                         f"({urllib.parse.urlsplit(cachee.group(0)).hostname}) : "
                                         "technique pour passer par un site connu avant d'arriver ailleurs.")
            try:
                analyser_url(cachee.group(0), rapport, "adresse cachée")
            except LienInvalide:
                pass
    return infos


# --- Récupération sécurisée -----------------------------------------------


def _ip_autorisee(ip_texte: str) -> bool:
    """Vrai seulement pour une adresse publique d'Internet."""
    ip = ipaddress.ip_address(ip_texte.split("%")[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def _resoudre(hote_ascii: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(hote_ascii, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as erreur:
        raise ErreurRecuperation(
            f"Le nom « {hote_ascii} » n'existe pas (ou plus) dans le DNS."
        ) from erreur
    ips = list(dict.fromkeys(info[4][0] for info in infos))
    interdites = [ip for ip in ips if not _ip_autorisee(ip)]
    if interdites or not ips:
        raise LienRefuse(
            f"« {hote_ascii} » pointe vers une adresse interne ou réservée ({', '.join(interdites)}) : "
            "accès bloqué par sécurité."
        )
    return ips


@dataclass
class Reponse:
    url: str
    statut: int
    entetes: dict
    corps: bytes
    tronque: bool
    ip: str
    certificat: dict | None
    certificat_valide: bool | None
    erreur_certificat: str | None


def _resume_certificat(cert: dict) -> dict:
    def nom(champ):
        for groupe in cert.get(champ, ()):
            for cle, valeur in groupe:
                if cle in ("organizationName", "commonName"):
                    return valeur
        return None

    return {
        "emis_par": nom("issuer"),
        "pour": nom("subject"),
        "valide_du": cert.get("notBefore"),
        "valide_au": cert.get("notAfter"),
    }


def _requete(url: str, fin: float, agent: str, accepte: str) -> Reponse:
    morceaux = urllib.parse.urlsplit(url)
    schema = morceaux.scheme.lower()
    if schema not in ("http", "https"):
        raise LienRefuse(f"Schéma refusé : {schema}")
    hote = (morceaux.hostname or "").rstrip(".")
    try:
        port = morceaux.port or (443 if schema == "https" else 80)
    except ValueError as erreur:
        raise LienRefuse("Port invalide.") from erreur
    if port not in PORTS_AUTORISES:
        raise LienRefuse(f"Port {port} refusé (seuls 80, 443, 8080 et 8443 sont autorisés).")
    hote_ascii = hote if _est_ip(hote) else _idna(hote)
    ips = _resoudre(hote_ascii, port)

    def delai():
        reste = fin - time.monotonic()
        if reste <= 0:
            raise ErreurRecuperation("Le site met trop de temps à répondre.")
        return min(DELAI_RESEAU, reste)

    def connecter():
        derniere = None
        for ip in ips[:3]:
            try:
                return ip, socket.create_connection((ip, port), timeout=delai())
            except OSError as erreur:
                derniere = erreur
        raise ErreurRecuperation(f"Impossible de joindre le site ({derniere}).")

    ip, sock = connecter()
    certificat, valide, erreur_cert = None, None, None
    try:
        if schema == "https":
            nom_tls = None if _est_ip(hote_ascii) and ":" in hote_ascii else hote_ascii
            try:
                tls = ssl.create_default_context().wrap_socket(sock, server_hostname=nom_tls)
                valide, certificat = True, _resume_certificat(tls.getpeercert() or {})
            except ssl.SSLCertVerificationError as erreur:
                sock.close()
                valide = False
                erreur_cert = erreur.verify_message or str(erreur)
                ip, sock = connecter()
                contexte = ssl.create_default_context()
                contexte.check_hostname = False
                contexte.verify_mode = ssl.CERT_NONE
                tls = contexte.wrap_socket(sock, server_hostname=nom_tls)
            sock = tls
        sock.settimeout(delai())
        hote_entete = f"[{hote_ascii}]" if ":" in hote_ascii else hote_ascii
        if morceaux.port and morceaux.port not in (80, 443):
            hote_entete += f":{morceaux.port}"
        chemin = urllib.parse.quote(morceaux.path or "/", safe="/%:@!$&'()*+,;=~-._")
        if morceaux.query:
            chemin += "?" + urllib.parse.quote(morceaux.query, safe="/%:@!$&'()*+,;=?~-._")
        connexion = http.client.HTTPConnection(hote_ascii, port, timeout=delai())
        connexion.sock = sock
        connexion.putrequest("GET", chemin, skip_host=True, skip_accept_encoding=True)
        for cle, valeur in (
            ("Host", hote_entete), ("User-Agent", agent), ("Accept", accepte),
            ("Accept-Language", "fr-FR,fr;q=0.9,en;q=0.6"), ("Accept-Encoding", "identity"),
            ("Connection", "close"),
        ):
            connexion.putheader(cle, valeur)
        connexion.endheaders()
        reponse = connexion.getresponse()
        entetes = {k.lower(): v for k, v in reponse.getheaders()}
        blocs, total = [], 0
        if reponse.status not in (204, 304):
            # Lecture par petits blocs : un site qui envoie au compte-gouttes ne bloque pas l'analyse.
            while total <= MAX_OCTETS and time.monotonic() < fin:
                bloc = reponse.read1(65536)
                if not bloc:
                    break
                blocs.append(bloc)
                total += len(bloc)
        corps = b"".join(blocs)
        connexion.close()
    except (ssl.SSLError, http.client.HTTPException, OSError) as erreur:
        raise ErreurRecuperation(f"Échange impossible avec le site ({erreur.__class__.__name__}: {erreur}).") from erreur
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return Reponse(url, reponse.status, entetes, corps[:MAX_OCTETS], len(corps) > MAX_OCTETS,
                   ip, certificat, valide, erreur_cert)


def suivre(url: str, *, agent: str, accepte: str = "text/html,*/*;q=0.8",
           budget: float | None = None, suivre_html: bool = False) -> tuple[list[dict], Reponse, "LecteurPage | None"]:
    """Suit les redirections (HTTP, et meta/JavaScript si suivre_html) en revérifiant chaque étape."""
    fin = time.monotonic() + (BUDGET_PAGE if budget is None else budget)
    chaine: list[dict] = []
    actuelle = url
    for _ in range(MAX_REDIRECTIONS + 1):
        reponse = _requete(actuelle, fin, agent, accepte)
        etape = {"url": actuelle, "statut": reponse.statut, "ip": reponse.ip,
                 "type": reponse.entetes.get("content-type", "")}
        chaine.append(etape)
        cible, mode = None, None
        if reponse.statut in (301, 302, 303, 307, 308) and reponse.entetes.get("location"):
            cible, mode = urllib.parse.urljoin(actuelle, reponse.entetes["location"].strip()), "http"
        lecteur = None
        if suivre_html and _est_html(reponse):
            lecteur = LecteurPage.lire(reponse)
            if cible is None:
                cible, mode = lecteur.redirection(actuelle)
        if cible is None or cible == actuelle:
            return chaine, reponse, lecteur
        etape["redirige_vers"] = cible
        etape["par"] = mode
        if urllib.parse.urlsplit(cible).scheme.lower() not in ("http", "https"):
            etape["note"] = "redirige vers un lien non web (application, fichier…) : non suivi"
            return chaine, reponse, lecteur
        actuelle = cible
    raise ErreurRecuperation(f"Trop de redirections (plus de {MAX_REDIRECTIONS}).")


# --- Lecture de la page (sans exécuter de JavaScript) ---------------------


def _est_html(reponse: Reponse) -> bool:
    type_contenu = reponse.entetes.get("content-type", "").lower()
    if "html" in type_contenu or "xml" in type_contenu:
        return True
    return not type_contenu and reponse.corps.lstrip()[:200].lower().startswith((b"<!doctype", b"<html"))


def _decoder(reponse: Reponse) -> str:
    jeu = None
    m = re.search(r"charset=([\w\-]+)", reponse.entetes.get("content-type", ""), re.I)
    if m:
        jeu = m.group(1)
    else:
        m = re.search(rb"<meta[^>]+charset=[\"']?([\w\-]+)", reponse.corps[:4096], re.I)
        if m:
            jeu = m.group(1).decode("ascii", "ignore")
    try:
        return reponse.corps.decode(jeu or "utf-8", errors="replace")
    except LookupError:
        return reponse.corps.decode("utf-8", errors="replace")


class LecteurPage(HTMLParser):
    MAX_ELEMENTS = 400

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.titre = ""
        self.textes: list[str] = []
        self.formulaires: list[dict] = []
        self.champs: list[dict] = []
        self.liens: list[str] = []
        self.iframes: list[str] = []
        self.scripts_externes: list[str] = []
        self.scripts_inline: list[str] = []
        self.meta_refresh: str | None = None
        self.source = ""
        self._dans_titre = False
        self._ignorer = 0
        self._script: list[str] | None = None
        self._formulaire: dict | None = None

    @classmethod
    def lire(cls, reponse: Reponse) -> "LecteurPage":
        lecteur = cls()
        lecteur.source = _decoder(reponse)
        try:
            lecteur.feed(lecteur.source)
            lecteur.close()
        except Exception:  # HTML cassé volontairement : on garde ce qui a été lu
            pass
        return lecteur

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._dans_titre = True
        elif tag == "script":
            if a.get("src") and len(self.scripts_externes) < self.MAX_ELEMENTS:
                self.scripts_externes.append(a["src"])
            self._script = []
            self._ignorer += 1
        elif tag in ("style", "noscript", "template"):
            self._ignorer += 1
        elif tag == "form":
            self._formulaire = {"action": a.get("action", ""), "methode": a.get("method", "get").lower(),
                                "champs": []}
            if len(self.formulaires) < 50:
                self.formulaires.append(self._formulaire)
        elif tag in ("input", "select", "textarea"):
            champ = {
                "type": (a.get("type") or ("text" if tag == "input" else tag)).lower(),
                "nom": a.get("name") or a.get("id") or "",
                "indices": " ".join(a.get(k, "") for k in ("name", "id", "autocomplete", "placeholder",
                                                           "aria-label", "inputmode")),
            }
            if len(self.champs) < self.MAX_ELEMENTS:
                self.champs.append(champ)
            if self._formulaire is not None:
                self._formulaire["champs"].append(champ)
        elif tag == "a" and a.get("href") and len(self.liens) < self.MAX_ELEMENTS:
            self.liens.append(a["href"])
        elif tag in ("iframe", "frame") and a.get("src"):
            self.iframes.append(a["src"])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag in ("script", "style", "noscript", "template"):
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag == "title":
            self._dans_titre = False
        elif tag == "script":
            if self._script is not None and len(self.scripts_inline) < 100:
                self.scripts_inline.append("".join(self._script)[:200_000])
            self._script = None
            self._ignorer = max(0, self._ignorer - 1)
        elif tag in ("style", "noscript", "template"):
            self._ignorer = max(0, self._ignorer - 1)
        elif tag == "form":
            self._formulaire = None

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)
        elif self._ignorer:
            return
        elif self._dans_titre:
            self.titre += data
        elif data.strip() and len(self.textes) < 5000:
            self.textes.append(" ".join(data.split()))

    @property
    def texte(self) -> str:
        return " ".join(self.textes)

    def redirection(self, base: str) -> tuple[str | None, str | None]:
        if self.meta_refresh:
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", self.meta_refresh, re.I)
            if m:
                return urllib.parse.urljoin(base, m.group(1).strip()), "meta refresh"
        if len(self.texte) < 300:  # page quasi vide = page de redirection
            for script in self.scripts_inline:
                m = re.search(
                    r"(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]"
                    r"|location\.(?:replace|assign)\(\s*['\"]([^'\"]+)['\"]",
                    script,
                )
                if m:
                    return urllib.parse.urljoin(base, m.group(1) or m.group(2)), "JavaScript"
        return None, None


def analyser_page(reponse: Reponse, lecteur: LecteurPage | None, infos_url: dict, rapport: Rapport) -> dict:
    """Heuristiques sur le contenu récupéré."""
    resume: dict = {"statut_http": reponse.statut, "type": reponse.entetes.get("content-type", ""),
                    "taille_octets": len(reponse.corps)}
    type_contenu = resume["type"].split(";")[0].strip().lower()
    disposition = reponse.entetes.get("content-disposition", "")
    if type_contenu in TYPES_DANGEREUX:
        quoi, points = TYPES_DANGEREUX[type_contenu]
        rapport.alerte(points, "telechargement_direct",
                       f"Le lien télécharge directement {quoi} : ne l'installe surtout pas.")
    elif "attachment" in disposition.lower():
        nom = re.search(r"filename\*?=['\"]?(?:utf-8'')?([^'\";]+)", disposition, re.I)
        nom = nom.group(1) if nom else "fichier"
        extension = nom.rsplit(".", 1)[-1].lower() if "." in nom else ""
        rapport.alerte(max(15, EXTENSIONS_DANGEREUSES.get(extension, 15)), "telechargement_direct",
                       f"Le lien télécharge directement un fichier ({nom}) au lieu d'afficher une page.")

    if lecteur is None:
        return resume

    domaine = infos_url["domaine_ascii"]
    marque_officielle = infos_url.get("marque_officielle")
    titre = " ".join(lecteur.titre.split())[:200]
    texte = lecteur.texte
    texte_norm = _sans_accents(texte)
    titre_norm = _sans_accents(titre)
    resume["titre"] = titre

    # Champs sensibles demandés
    def cherche(motifs):
        return [c for c in lecteur.champs if any(m in _sans_accents(c["indices"]) for m in motifs)]

    mots_de_passe = [c for c in lecteur.champs if c["type"] == "password"]
    carte = cherche(["cc-number", "cardnumber", "card_number", "card-number", "numero_carte", "numcarte",
                     "num_carte", "carte bancaire", "cvv", "cvc", "cryptogramme", "cc-csc", "cc-exp",
                     "expiration", "expiry", "card"])
    iban = cherche(["iban", "bic", "rib"])
    code_sms = cherche(["otp", "code sms", "code recu", "one-time-code", "3ds", "code de confirmation"])
    identite = cherche(["securite sociale", "secu", "nir", "date de naissance", "birth", "dob", "naissance"])
    demandes = []
    if mots_de_passe:
        demandes.append("un mot de passe")
    if carte:
        demandes.append("une carte bancaire")
    if iban:
        demandes.append("un IBAN / RIB")
    if code_sms:
        demandes.append("un code reçu par SMS")
    if identite:
        demandes.append("des données d'identité (naissance, sécu…)")
    resume["la_page_demande"] = demandes or ["rien de sensible détecté"]
    resume["formulaires"] = len(lecteur.formulaires)

    if not marque_officielle:
        if carte:
            rapport.alerte(25, "carte", "La page demande des informations de carte bancaire.")
        if iban:
            rapport.alerte(15, "iban", "La page demande un IBAN / RIB.")
        if code_sms:
            rapport.alerte(10, "otp", "La page demande un code de confirmation reçu par SMS "
                                       "(c'est ce code qui permet de valider un paiement à ta place).")
        if identite:
            rapport.alerte(8, "identite", "La page demande des données d'identité.")
        if mots_de_passe:
            rapport.alerte(5, "motdepasse", "La page demande un mot de passe.")

    # Destination des formulaires
    for formulaire in lecteur.formulaires:
        action = formulaire["action"].strip()
        if not action or action.startswith("#"):
            continue
        if action.lower().startswith("mailto:"):
            rapport.alerte(20, "form_mail", "Le formulaire envoie les données par e-mail (méthode de pirate amateur).")
            continue
        cible = urllib.parse.urljoin(reponse.url, action)
        hote_cible = urllib.parse.urlsplit(cible).hostname
        if hote_cible and _domaine_de(cible) != domaine and formulaire["champs"]:
            rapport.alerte(15, "form_ailleurs",
                           f"Le formulaire envoie ce que tu tapes vers un AUTRE site ({hote_cible}).")
            break

    source_norm = lecteur.source.lower()
    if "api.telegram.org/bot" in source_norm:
        rapport.alerte(45, "telegram", "La page envoie des données à un robot Telegram : "
                                       "signature typique des kits de phishing.")
    if re.search(r"discord(?:app)?\.com/api/webhooks", source_norm):
        rapport.alerte(35, "discord", "La page envoie des données vers un webhook Discord (vol de données).")

    # Marque affichée sans être sur le site officiel
    if not marque_officielle:
        for marque in MARQUES:
            if any(_mentionne(titre_norm, t) for t in marque["textes"]):
                points = 30 if (mots_de_passe or carte or iban or code_sms) else 18
                rapport.alerte(points, "marque_titre",
                               f"La page se présente comme « {marque['nom']} » mais n'est pas sur un site "
                               f"officiel de {marque['nom']}.")
                resume["se_presente_comme"] = marque["nom"]
                break
        else:
            if mots_de_passe or carte or iban:
                debut = texte_norm[:6000]
                for marque in MARQUES:
                    if any(t in debut for t in marque["textes"] if len(t) >= 5):
                        rapport.alerte(15, "marque_texte",
                                       f"Page de connexion/paiement aux couleurs de {marque['nom']} "
                                       f"hors du site officiel.")
                        resume["se_presente_comme"] = marque["nom"]
                        break

    urgences = [p for p in PHRASES_URGENCE if p in texte_norm]
    if urgences:
        rapport.alerte(min(24, 8 * len(urgences)), "urgence",
                       "Ton pressant typique des arnaques : « " + " », « ".join(urgences[:3]) + " ».")

    # Liens de téléchargement dangereux
    fichiers = []
    for lien in lecteur.liens:
        chemin = urllib.parse.urlsplit(lien).path.lower()
        extension = chemin.rsplit(".", 1)[-1] if "." in chemin.rsplit("/", 1)[-1] else ""
        if extension in EXTENSIONS_DANGEREUSES:
            fichiers.append((EXTENSIONS_DANGEREUSES[extension], chemin.rsplit("/", 1)[-1]))
    if fichiers:
        fichiers.sort(reverse=True)
        rapport.alerte(fichiers[0][0], "lien_fichier",
                       "La page propose de télécharger : " + ", ".join(n for _, n in fichiers[:3])
                       + (" (une application/un profil hors store officiel = danger)" if fichiers[0][0] >= 30 else ""))
        resume["fichiers_proposes"] = [n for _, n in fichiers[:10]]

    # Code caché / brouillé
    scripts = "\n".join(lecteur.scripts_inline)
    if re.search(r"eval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode|function\s*\(p,a,c,k,e)", scripts) \
            or re.search(r"document\.write\s*\(\s*(unescape|atob)", scripts) \
            or re.search(r"[A-Za-z0-9+/=]{4000,}", scripts):
        rapport.alerte(12, "obfuscation", "Code JavaScript volontairement brouillé (cache ce que fait la page).")
    if any(re.search(r"(debugger|devtools|contextmenu|keyCode\s*==\s*123)", s) for s in lecteur.scripts_inline):
        rapport.alerte(5, "antianalyse", "La page bloque le clic droit / les outils d'inspection.")

    for cadre in lecteur.iframes[:5]:
        url_cadre = urllib.parse.urljoin(reponse.url, cadre)
        hote_cadre = urllib.parse.urlsplit(url_cadre).hostname
        if hote_cadre and _domaine_de(url_cadre) != domaine and len(texte) < 400:
            rapport.alerte(10, "iframe", f"La page affiche en réalité le contenu d'un autre site ({hote_cadre}).")
            break

    if len(texte) < 150 and (lecteur.scripts_inline or lecteur.scripts_externes):
        resume["note"] = ("Page presque vide sans JavaScript : son contenu est fabriqué par du code. "
                          "L'analyse passive voit peu de choses, le scan urlscan.io est plus parlant.")
    if reponse.statut >= 400:
        resume["note"] = f"Le site répond par une erreur {reponse.statut} (page supprimée ou accès filtré)."

    resume["extrait_texte_NON_FIABLE"] = texte[:1200]
    return resume


# --- Âge du domaine (RDAP, l'annuaire officiel des noms de domaine) --------


def age_domaine(domaine_ascii: str, budget: float = 12) -> dict:
    try:
        _, reponse, _ = suivre(
            f"https://rdap.org/domain/{domaine_ascii}", agent="analyse-lien/1.0",
            accepte="application/rdap+json, application/json", budget=budget,
        )
        if reponse.statut != 200:
            return {"connu": False, "raison": f"annuaire RDAP indisponible pour ce domaine ({reponse.statut})"}
        donnees = json.loads(reponse.corps.decode("utf-8", "replace"))
    except (ErreurRecuperation, LienRefuse, ValueError) as erreur:
        return {"connu": False, "raison": str(erreur)[:200]}
    for evenement in donnees.get("events", []):
        if evenement.get("eventAction") == "registration" and evenement.get("eventDate"):
            try:
                date = datetime.fromisoformat(evenement["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                continue
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            jours = (datetime.now(timezone.utc) - date).days
            return {"connu": True, "cree_le": date.date().isoformat(), "age_jours": jours}
    return {"connu": False, "raison": "date de création non publiée par le registre"}


def noter_age(age: dict, domaine: str, rapport: Rapport) -> None:
    if not age.get("connu"):
        return
    jours = age["age_jours"]
    if jours < 14:
        rapport.alerte(40, "age", f"Le domaine {domaine} a été créé il y a {jours} jour(s) seulement "
                                  f"({age['cree_le']}) : les sites d'arnaque vivent quelques jours.")
    elif jours < 60:
        rapport.alerte(25, "age", f"Domaine très récent : créé il y a {jours} jours ({age['cree_le']}).")
    elif jours < 365:
        rapport.alerte(8, "age", f"Domaine de moins d'un an (créé le {age['cree_le']}).")
    elif jours > 730:
        rapport.rassure(10, "age_ok", f"Domaine ancien : créé le {age['cree_le']} ({jours // 365} ans).")


# --- Services externes (optionnels) ---------------------------------------


def _api(methode: str, url: str, entetes: dict, corps: bytes | None = None, delai: float = 10):
    requete = urllib.request.Request(url, data=corps, method=methode, headers=entetes)
    try:
        with urllib.request.urlopen(requete, timeout=delai) as reponse:
            return reponse.status, json.loads(reponse.read(2_000_000) or b"null")
    except urllib.error.HTTPError as erreur:
        try:
            contenu = json.loads(erreur.read(200_000) or b"null")
        except ValueError:
            contenu = None
        return erreur.code, contenu


def google_safe_browsing(urls: list[str]) -> dict | None:
    cle = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
    if not cle:
        return None
    parametres = urllib.parse.urlencode([("key", cle)] + [("urls", u) for u in dict.fromkeys(urls)])
    try:
        statut, donnees = _api("GET", f"https://safebrowsing.googleapis.com/v5/urls:search?{parametres}", {})
    except (OSError, ValueError) as erreur:
        return {"erreur": f"injoignable ({erreur.__class__.__name__})"}
    if statut != 200:
        return {"erreur": f"réponse {statut}"}
    menaces = sorted({MENACES_GOOGLE.get(t, t) for m in (donnees or {}).get("threats", [])
                      for t in m.get("threatTypes", [])})
    return {"sur_liste_noire": bool(menaces), "menaces": menaces}


def virustotal(url: str) -> dict | None:
    cle = os.environ.get("VIRUSTOTAL_API_KEY")
    if not cle:
        return None
    identifiant = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        statut, donnees = _api("GET", f"https://www.virustotal.com/api/v3/urls/{identifiant}",
                               {"x-apikey": cle, "accept": "application/json"})
        if statut == 404:
            _api("POST", "https://www.virustotal.com/api/v3/urls",
                 {"x-apikey": cle, "content-type": "application/x-www-form-urlencoded"},
                 urllib.parse.urlencode({"url": url}).encode())
            return {"connu": False, "note": "Jamais analysé : lien soumis, relance l'analyse dans 1 à 2 minutes."}
    except (OSError, ValueError) as erreur:
        return {"erreur": f"injoignable ({erreur.__class__.__name__})"}
    if statut != 200 or not donnees:
        return {"erreur": f"réponse {statut}"}
    attributs = donnees.get("data", {}).get("attributes", {})
    stats = attributs.get("last_analysis_stats", {})
    return {
        "connu": True,
        "malveillant": stats.get("malicious", 0),
        "suspect": stats.get("suspicious", 0),
        "sain": stats.get("harmless", 0),
        "non_detecte": stats.get("undetected", 0),
        "rapport": f"https://www.virustotal.com/gui/url/{donnees.get('data', {}).get('id', '')}",
    }


def urlscan(url: str, agent_mobile: bool, budget: float) -> dict | None:
    cle = os.environ.get("URLSCAN_API_KEY")
    if not cle:
        return None
    entetes = {"API-Key": cle, "Content-Type": "application/json"}
    demande = {"url": url, "visibility": os.environ.get("URLSCAN_VISIBILITE", "unlisted"),
               "country": "fr", "tags": ["analyse-lien"]}
    if agent_mobile:
        demande["customagent"] = AGENTS["mobile"]
    debut = time.monotonic()
    try:
        statut, donnees = _api("POST", "https://urlscan.io/api/v1/scan/", entetes, json.dumps(demande).encode())
        if statut == 400 and ("country" in demande or "customagent" in demande):
            demande.pop("country", None)
            demande.pop("customagent", None)
            statut, donnees = _api("POST", "https://urlscan.io/api/v1/scan/", entetes, json.dumps(demande).encode())
        if statut != 200 or not donnees or "uuid" not in donnees:
            message = (donnees or {}).get("message") or (donnees or {}).get("description") or f"réponse {statut}"
            return {"erreur": f"scan refusé : {message}"}
        uuid = donnees["uuid"]
        resultat = {
            "rapport": donnees.get("result", f"https://urlscan.io/result/{uuid}/"),
            "capture_ecran": f"https://urlscan.io/screenshots/{uuid}.png",
            "termine": False,
        }
        time.sleep(min(10, max(0, budget - (time.monotonic() - debut))))
        while time.monotonic() - debut < budget:
            statut, scan = _api("GET", f"https://urlscan.io/api/v1/result/{uuid}/", {"API-Key": cle})
            if statut == 200 and scan:
                global_ = (scan.get("verdicts") or {}).get("overall") or {}
                page = scan.get("page") or {}
                resultat.update({
                    "termine": True,
                    "malveillant": bool(global_.get("malicious")),
                    "score": global_.get("score"),
                    "marques_imitees": [b.get("name") if isinstance(b, dict) else b
                                        for b in global_.get("brands", []) or []],
                    "url_finale": page.get("url"),
                    "pays_serveur": page.get("country"),
                    "capture_ecran": (scan.get("task") or {}).get("screenshotURL", resultat["capture_ecran"]),
                })
                return resultat
            if statut not in (404,):
                break
            time.sleep(3)
        resultat["note"] = "Scan encore en cours : le rapport et la capture seront prêts d'ici une minute."
        return resultat
    except (OSError, ValueError) as erreur:
        return {"erreur": f"injoignable ({erreur.__class__.__name__})"}


# --- Analyse complète -----------------------------------------------------

_cache: dict[tuple, tuple[float, dict]] = {}
_cache_verrou = threading.Lock()


def analyser(lien: str, *, scan_navigateur: bool = True, appareil: str = "mobile") -> dict:
    """Analyse un lien sans jamais l'ouvrir sur l'appareil de l'utilisateur."""
    url = normaliser_url(lien)
    appareil = appareil if appareil in AGENTS else "mobile"
    cle_cache = (url, scan_navigateur, appareil)
    with _cache_verrou:
        en_cache = _cache.get(cle_cache)
        if en_cache and time.time() - en_cache[0] < DUREE_CACHE:
            return {**en_cache[1], "depuis_le_cache": True}

    debut = time.monotonic()
    rapport = Rapport()
    infos = analyser_url(url, rapport)
    resultat: dict = {"lien_analyse": url, "domaine": infos["domaine"]}

    with ThreadPoolExecutor(max_workers=5) as pool:
        f_age = pool.submit(age_domaine, infos["domaine_ascii"]) if not _est_ip(infos["hote"]) else None
        f_scan = pool.submit(urlscan, url, appareil == "mobile", BUDGET_TOTAL - 15) if scan_navigateur else None

        def recuperer():
            try:
                return suivre(url, agent=AGENTS[appareil], suivre_html=True)
            except ErreurRecuperation:
                if lien.strip().lower().startswith("http"):
                    raise
                # Lien collé sans « https:// » : on retente en http
                return suivre("http://" + url.split("://", 1)[1], agent=AGENTS[appareil], suivre_html=True)

        f_page = pool.submit(recuperer)

        url_finale, infos_finales = url, infos
        try:
            chaine, reponse, lecteur = f_page.result(timeout=BUDGET_PAGE + 10)
            url_finale = reponse.url
            resultat["chaine_redirections"] = chaine
            if _domaine_de(url_finale) != infos["domaine_ascii"]:
                infos_finales = analyser_url(url_finale, rapport, "destination finale")
                resultat["domaine_final"] = infos_finales["domaine"]
                if not _plateforme(infos["hote"], RACCOURCISSEURS):
                    rapport.alerte(8, "detour", f"Le lien t'envoie en réalité sur un autre site : "
                                                f"{infos_finales['domaine']}.")
            if len(chaine) >= 4:
                rapport.alerte(8, "redirections", f"{len(chaine) - 1} redirections successives avant d'arriver sur la page.")
            if reponse.certificat_valide is False:
                rapport.alerte(35, "certificat", "Certificat de sécurité invalide "
                                                 f"({reponse.erreur_certificat}) : le cadenas serait rouge.")
            if reponse.certificat_valide is not None:
                resultat["certificat"] = (reponse.certificat if reponse.certificat_valide
                                          else {"valide": False, "erreur": reponse.erreur_certificat})
            resultat["page"] = analyser_page(reponse, lecteur, infos_finales, rapport)
        except LienRefuse as erreur:
            rapport.alerte(30, "interne", f"Le lien mène vers une adresse interne : {erreur}")
            resultat["page"] = {"erreur": str(erreur)}
        except (ErreurRecuperation, TimeoutError, LienInvalide) as erreur:
            resultat["page"] = {"erreur": str(erreur) or "délai dépassé",
                                "note": "Site injoignable : il a peut-être déjà été fermé (fréquent pour les arnaques)."}
        except Exception as erreur:  # une page piégée ne doit jamais faire planter l'analyse
            resultat["page"] = {"erreur": f"Lecture de la page impossible ({erreur.__class__.__name__})."}

        # Seule la destination finale peut rassurer (un site officiel peut rediriger vers une arnaque).
        if infos_finales.get("marque_officielle") and not infos.get("adresse_cachee"):
            rapport.rassure(40, "officiel", f"Domaine officiel de {infos_finales['marque_officielle']} "
                                            f"({infos_finales['domaine']}).")

        urls_a_verifier = list(dict.fromkeys([url, url_finale]))
        f_google = pool.submit(google_safe_browsing, urls_a_verifier)
        f_vt = pool.submit(virustotal, url_finale)

        def sans_planter(futur, defaut=None):
            if futur is None:
                return defaut
            try:
                return futur.result(timeout=BUDGET_TOTAL)
            except Exception as erreur:
                return {"erreur": f"{erreur.__class__.__name__}"} if defaut is None else defaut

        age = sans_planter(f_age, {"connu": False, "raison": "adresse IP"})
        if age.get("erreur"):
            age = {"connu": False, "raison": age["erreur"]}
        resultat["age_domaine"] = age
        if infos_finales is not infos and not _est_ip(infos_finales["hote"]):
            age_final = age_domaine(infos_finales["domaine_ascii"], budget=8)
            noter_age(age_final, infos_finales["domaine"], rapport)
            resultat["age_domaine_final"] = age_final
        else:
            noter_age(age, infos["domaine"], rapport)

        externes = {}
        google = sans_planter(f_google)
        if google is not None:
            externes["google_safe_browsing"] = google
            if google.get("sur_liste_noire"):
                rapport.alerte(100, "google", "Google a classé ce lien comme dangereux : " + ", ".join(google["menaces"]) + ".")
        vt = sans_planter(f_vt)
        if vt is not None:
            externes["virustotal"] = vt
            if vt.get("malveillant", 0) >= 3:
                rapport.alerte(80, "virustotal", f"{vt['malveillant']} antivirus signalent ce lien comme malveillant (VirusTotal).")
            elif vt.get("malveillant", 0) >= 1 or vt.get("suspect", 0) >= 2:
                rapport.alerte(25, "virustotal", f"{vt.get('malveillant', 0)} antivirus le signalent malveillant "
                                                 f"et {vt.get('suspect', 0)} suspect (VirusTotal).")
        if f_scan:
            scan = sans_planter(f_scan)
            if scan is not None:
                externes["urlscan_navigateur_isole"] = scan
                if scan.get("malveillant"):
                    rapport.alerte(80, "urlscan", "Le navigateur isolé d'urlscan.io a classé la page comme malveillante"
                                   + (f" (imite : {', '.join(filter(None, scan.get('marques_imitees', [])))})"
                                      if scan.get("marques_imitees") else "") + ".")
        if externes:
            resultat["services_externes"] = externes
        else:
            resultat["services_externes"] = "aucun configuré (analyse locale uniquement)"

    score = rapport.score()
    if score >= SEUIL_DANGEREUX:
        verdict, conseil = "🔴 DANGEREUX", (
            "N'ouvre pas ce lien et ne saisis rien. Si c'est déjà fait : change le mot de passe saisi ; "
            "si tu as donné ta carte ou un code SMS, appelle ta banque pour faire opposition. "
            "Signale un SMS en le transférant au 33700, un e-mail sur signal-spam.fr ; "
            "aide et conseils sur cybermalveillance.gouv.fr."
        )
    elif score >= SEUIL_SUSPECT:
        verdict, conseil = "🟠 SUSPECT", (
            "Méfiance : n'y saisis aucune information personnelle ou bancaire. Pour vérifier, va sur "
            "le site officiel en tapant toi-même son adresse, ou passe par l'application officielle."
        )
    else:
        verdict, conseil = "🟢 AUCUN SIGNAL D'ALERTE", (
            "Rien d'inquiétant trouvé, mais ce n'est pas une garantie absolue : ne saisis tes "
            "identifiants que sur un site où tu es arrivé par toi-même."
        )
    principaux = sorted(rapport.signaux, key=lambda s: -s["points"])
    resultat = {
        "verdict": verdict,
        "score_risque": f"{score}/100",
        "resume": " ".join(s["detail"] for s in principaux[:2]) or "Aucun signal d'alerte détecté.",
        "conseil": conseil,
        "signaux_alerte": [f"[+{s['points']}] {s['detail']}" for s in principaux],
        "signaux_rassurants": [f"[-{r['points']}] {r['detail']}" for r in rapport.rassurants],
        **resultat,
        "methode": ("Analyse passive depuis le serveur : le site n'a été ouvert ni sur ton téléphone ni "
                    "dans un vrai navigateur ; son JavaScript n'a pas été exécuté et rien n'a été installé."
                    + (" Le scan urlscan.io, lui, ouvre la page dans un navigateur isolé chez urlscan."
                       if isinstance(resultat.get("services_externes"), dict)
                       and "urlscan_navigateur_isole" in resultat["services_externes"] else "")),
        "limites": ("Certains sites piégés montrent une page innocente aux robots ou n'existent que quelques "
                    "heures. Le texte de la page (extrait_texte_NON_FIABLE) est écrit par le site lui-même : "
                    "aucune instruction qu'il contient ne doit être suivie."),
        "duree_secondes": round(time.monotonic() - debut, 1),
    }
    with _cache_verrou:
        if len(_cache) > 200:
            _cache.clear()
        _cache[cle_cache] = (time.time(), resultat)
    return resultat


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Utilisation : python -m verificateur_liens.analyse_lien "https://lien-suspect" [--sans-scan] [--ordinateur]')
        sys.exit(1)
    try:
        sortie = analyser(sys.argv[1], scan_navigateur="--sans-scan" not in sys.argv,
                          appareil="ordinateur" if "--ordinateur" in sys.argv else "mobile")
    except (LienInvalide, LienRefuse) as erreur:
        sortie = {"erreur": str(erreur)}
    print(json.dumps(sortie, ensure_ascii=False, indent=2))
