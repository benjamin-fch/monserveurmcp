"""Serveur d'autorisation OAuth 2.1 « sans état » pour le serveur MCP.

Les IA (Claude, France Student IA, VS Code...) se connectent avec le flux OAuth
standard de MCP : enregistrement dynamique du client, page d'autorisation, puis
échange du code contre un jeton d'accès renouvelable.

La page d'autorisation demande une passkey (Touch ID / Face ID), voir passkey.py.

« Sans état » : clients, codes et jetons sont des données signées (HMAC), pas des
entrées en mémoire. Un redémarrage de Render ne déconnecte donc personne. La clé
de signature dérive des secrets du serveur ET de la liste des passkeys : changer
l'un d'eux révoque immédiatement tous les accès.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
import zlib
from urllib.parse import urlencode, urlparse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

journal = logging.getLogger("oauth")

DUREE_ACCES = int(os.environ.get("OAUTH_ACCESS_TTL_SECONDS", str(3600)))
DUREE_RENOUVELLEMENT = int(os.environ.get("OAUTH_REFRESH_TTL_SECONDS", str(90 * 86400)))
DUREE_CODE = 300
DUREE_DEMANDE = 600


def _b64(donnees: bytes) -> str:
    return base64.urlsafe_b64encode(donnees).rstrip(b"=").decode()


def _deb64(texte: str) -> bytes:
    return base64.urlsafe_b64decode(texte + "=" * (-len(texte) % 4))


class Signataire:
    """Signe / vérifie de petites charges JSON typées (« typ ») avec expiration."""

    def __init__(self, cle: bytes) -> None:
        self._cle = cle

    def signer(self, typ: str, charge: dict, duree: int | None = None) -> str:
        donnees = {"typ": typ, **charge}
        if duree is not None:
            donnees["exp"] = int(time.time()) + duree
        brut = zlib.compress(json.dumps(donnees, separators=(",", ":")).encode(), 9)
        corps = _b64(brut)
        sig = _b64(hmac.new(self._cle, corps.encode(), hashlib.sha256).digest()[:24])
        return f"{corps}.{sig}"

    def verifier(self, typ: str, jeton: str) -> dict | None:
        try:
            corps, sig = jeton.split(".", 1)
            attendu = hmac.new(self._cle, corps.encode(), hashlib.sha256).digest()[:24]
            if not hmac.compare_digest(attendu, _deb64(sig)):
                return None
            donnees = json.loads(zlib.decompress(_deb64(corps)))
        except Exception:
            return None
        if donnees.get("typ") != typ:
            return None
        if "exp" in donnees and int(donnees["exp"]) <= time.time():
            return None
        return donnees

    def raison_refus(self, typ: str, jeton: str) -> str:
        """Explique pourquoi un jeton est refusé (pour les logs, sans le jeton)."""
        try:
            corps, sig = jeton.split(".", 1)
            attendu = hmac.new(self._cle, corps.encode(), hashlib.sha256).digest()[:24]
            if not hmac.compare_digest(attendu, _deb64(sig)):
                return "signature invalide (jeton d'une autre clé : PASSKEYS ou secret modifié depuis ?)"
            donnees = json.loads(zlib.decompress(_deb64(corps)))
        except Exception:
            return "format inconnu"
        if donnees.get("typ") != typ:
            return f"type {donnees.get('typ')!r} au lieu de {typ!r}"
        if "exp" in donnees and int(donnees["exp"]) <= time.time():
            return f"expiré depuis {int(time.time() - int(donnees['exp']))} s"
        return "valide"

    def derive(self, etiquette: str) -> str:
        return hmac.new(self._cle, etiquette.encode(), hashlib.sha256).hexdigest()


class UsageUnique:
    """Mémorise les identifiants déjà consommés (codes, défis) jusqu'à expiration."""

    def __init__(self) -> None:
        self._vus: dict[str, float] = {}
        self._verrou = threading.Lock()

    def consommer(self, jti: str, exp: float) -> bool:
        maintenant = time.time()
        with self._verrou:
            self._vus = {k: v for k, v in self._vus.items() if v > maintenant}
            if jti in self._vus:
                return False
            self._vus[jti] = exp
            return True

    def deja_vu(self, jti: str) -> bool:
        with self._verrou:
            return jti in self._vus


HOTES_LOCAUX = {"localhost", "127.0.0.1", "::1"}


def redirection_sure(uri: str) -> bool:
    """https partout, http seulement en local. Interdit javascript:, data:, etc."""
    try:
        u = urlparse(uri)
    except ValueError:
        return False
    if u.scheme == "https":
        return bool(u.hostname)
    return u.scheme == "http" and u.hostname in HOTES_LOCAUX


def hote_redirection(uri: str) -> str:
    return urlparse(uri).hostname or "?"


def cle_serveur(etiquette: str) -> bytes:
    """Clé dérivée des secrets du serveur et de la liste des passkeys."""
    materiel = "|".join(
        [
            etiquette,
            os.environ.get("MCP_API_TOKEN", ""),
            os.environ.get("MCP_TOTP_SECRET", ""),
            os.environ.get("PASSKEYS", ""),
        ]
    )
    return hashlib.sha256(materiel.encode()).digest()


class FournisseurOAuth:
    """Implémente OAuthAuthorizationServerProvider du SDK MCP."""

    def __init__(self, url_publique: str, verifier_session_2fa=None) -> None:
        self.url_publique = url_publique.rstrip("/")
        self.ressource = f"{self.url_publique}/mcp"
        self.signataire = Signataire(cle_serveur("oauth-v1"))
        self.codes_utilises = UsageUnique()
        # Jetons de session de l'ancienne double authentification (scripts locaux).
        self._session_2fa = verifier_session_2fa

    # --- clients (enregistrement dynamique, RFC 7591) ---------------------
    def _secret_client(self, client_id: str) -> str:
        return self.signataire.derive("client-secret|" + client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            if not redirection_sure(str(uri)):
                raise RegistrationError(
                    "invalid_redirect_uri",
                    "redirect_uri doit être en https (http accepté seulement pour localhost)",
                )
        meta = client_info.model_dump(
            mode="json",
            exclude={"client_id", "client_secret", "client_secret_expires_at"},
            exclude_none=True,
        )
        client_id = self.signataire.signer("cli", {"m": meta})
        # Le SDK renvoie cet objet tel quel au client : on y place nos valeurs.
        client_info.client_id = client_id
        if client_info.client_secret is not None:
            client_info.client_secret = self._secret_client(client_id)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        donnees = self.signataire.verifier("cli", client_id)
        if donnees is None:
            return None
        meta = donnees["m"]
        secret = None
        if meta.get("token_endpoint_auth_method", "client_secret_post") != "none":
            secret = self._secret_client(client_id)
        return OAuthClientInformationFull.model_validate(
            {
                **meta,
                "client_id": client_id,
                "client_secret": secret,
                "client_secret_expires_at": 0 if secret else None,
            }
        )

    # --- autorisation -----------------------------------------------------
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        demande = self.signataire.signer(
            "dem",
            {
                "cid": client.client_id,
                "nom": client.client_name or "Une application",
                "ru": str(params.redirect_uri),
                "rue": params.redirect_uri_provided_explicitly,
                "cc": params.code_challenge,
                "st": params.state,
                "sc": params.scopes or [],
                "res": params.resource,
            },
            DUREE_DEMANDE,
        )
        return f"{self.url_publique}/oauth/connexion?{urlencode({'r': demande})}"

    def lire_demande(self, demande: str) -> dict | None:
        return self.signataire.verifier("dem", demande)

    def accorder(self, demande: dict) -> str:
        """Appelé après une passkey valide : renvoie l'URL de retour avec le code."""
        if not redirection_sure(demande["ru"]):
            raise ValueError("redirect_uri refusée")
        code = self.signataire.signer(
            "code",
            {
                "cid": demande["cid"],
                "ru": demande["ru"],
                "rue": demande["rue"],
                "cc": demande["cc"],
                "sc": demande["sc"],
                "res": demande["res"],
                "jti": secrets.token_urlsafe(12),
            },
            DUREE_CODE,
        )
        return construct_redirect_uri(demande["ru"], code=code, state=demande["st"])

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        d = self.signataire.verifier("code", authorization_code)
        if d is None or d["cid"] != client.client_id or self.codes_utilises.deja_vu(d["jti"]):
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=d["sc"],
            expires_at=float(d["exp"]),
            client_id=d["cid"],
            code_challenge=d["cc"],
            redirect_uri=d["ru"],
            redirect_uri_provided_explicitly=d["rue"],
            resource=d["res"],
            subject="proprietaire",
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        d = self.signataire.verifier("code", authorization_code.code)
        if d is None or not self.codes_utilises.consommer(d["jti"], d["exp"]):
            raise TokenError("invalid_grant", "code déjà utilisé ou expiré")
        journal.info("Accès accordé à %s (ressource %s)", self._nom_client(client.client_id), authorization_code.resource)
        return self._emettre(client.client_id, authorization_code.scopes, authorization_code.resource)

    # --- jetons -----------------------------------------------------------
    def _emettre(self, client_id: str, scopes: list[str], ressource: str | None) -> OAuthToken:
        charge = {"cid": client_id, "sc": scopes, "res": ressource}
        acces = self.signataire.signer("acc", charge, DUREE_ACCES)
        renouv = self.signataire.signer("ref", {**charge, "n": secrets.token_urlsafe(6)}, DUREE_RENOUVELLEMENT)
        return OAuthToken(
            access_token=acces,
            token_type="Bearer",
            expires_in=DUREE_ACCES,
            refresh_token=renouv,
            scope=" ".join(scopes) if scopes else None,
        )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        d = self.signataire.verifier("ref", refresh_token)
        if d is None or d["cid"] != client.client_id:
            journal.warning("Renouvellement refusé : %s", self.signataire.raison_refus("ref", refresh_token)
                            if d is None else "client différent")
            return None
        journal.info("Renouvellement du jeton de %s", self._nom_client(d["cid"]))
        return RefreshToken(
            token=refresh_token,
            client_id=d["cid"],
            scopes=d["sc"],
            expires_at=int(d["exp"]),
            resource=d["res"],
            subject="proprietaire",
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        return self._emettre(client.client_id, scopes or refresh_token.scopes, refresh_token.resource)

    async def load_access_token(self, token: str) -> AccessToken | None:
        d = self.signataire.verifier("acc", token)
        if d is not None:
            # Jeton émis pour une autre ressource : refusé.
            if d["res"] and d["res"].rstrip("/") not in (self.ressource, self.url_publique):
                journal.warning("Jeton refusé : ressource %r au lieu de %r", d["res"], self.ressource)
                return None
            return AccessToken(
                token=token,
                client_id=d["cid"],
                scopes=d["sc"],
                expires_at=int(d["exp"]),
                resource=d["res"],
                subject="proprietaire",
            )
        if self._session_2fa and self._session_2fa(token):
            return AccessToken(token=token, client_id="session-2fa", scopes=[], subject="proprietaire")
        journal.warning("Jeton d'accès refusé : %s", self.signataire.raison_refus("acc", token))
        return None

    def _nom_client(self, client_id: str) -> str:
        d = self.signataire.verifier("cli", client_id)
        return (d or {}).get("m", {}).get("client_name") or "client inconnu"

    async def revoke_token(self, token) -> None:
        # Sans état : pas de révocation individuelle (changer PASSKEYS ou un
        # secret révoque tout). La route de révocation est désactivée.
        return None
