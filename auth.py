"""Double authentification : jeton secret (facteur 1) + code TOTP (facteur 2).

Principe :
  1. Le client appelle POST /auth/login avec {"token": ..., "code": ...}.
     Le serveur vérifie le jeton secret ET le code à 6 chiffres de l'application
     d'authentification (Google Authenticator, Authy, 1Password...).
  2. Il renvoie un jeton de session signé, à durée limitée.
  3. Ce jeton est accepté sur /mcp et /workspace.zip (scripts locaux).

Depuis l'arrivée des passkeys, cette double authentification ne sert plus qu'à
enregistrer une passkey (/passkey/installer) et aux scripts locaux. Les IA se
connectent par OAuth + passkey (voir oauth.py et passkey.py).

Les secrets restent dans les variables d'environnement (jamais dans le code) :
  MCP_API_TOKEN       facteur 1, 32 caractères minimum
  MCP_TOTP_SECRET     facteur 2, secret TOTP en base32
  SESSION_TTL_SECONDS durée d'une session (défaut 12 h)
Le serveur refuse de démarrer si l'un des deux secrets manque.
"""

import base64
import hashlib
import hmac
import json
import os
import threading
import time

import pyotp

PAS_TOTP = 30
ECHECS_MAX = 8
FENETRE_ECHECS = 600  # secondes
DUREE_BLOCAGE = 600  # secondes


class ConfigAuthError(RuntimeError):
    pass


class Authentificateur:
    def __init__(self) -> None:
        self._jeton = os.environ.get("MCP_API_TOKEN", "")
        self._secret_totp = os.environ.get("MCP_TOTP_SECRET", "").replace(" ", "")

        if len(self._jeton) < 32:
            raise ConfigAuthError(
                "MCP_API_TOKEN manquant ou trop court (32 caractères minimum). "
                "Lance `python setup_2fa.py` pour en générer un."
            )
        try:
            base64.b32decode(self._secret_totp.upper() + "=" * (-len(self._secret_totp) % 8))
        except Exception:
            self._secret_totp = ""
        if len(self._secret_totp) < 16:
            raise ConfigAuthError(
                "MCP_TOTP_SECRET manquant ou invalide (base32, 16 caractères minimum). "
                "Lance `python setup_2fa.py` pour en générer un."
            )

        self._totp = pyotp.TOTP(self._secret_totp)
        self._duree = int(os.environ.get("SESSION_TTL_SECONDS", str(12 * 3600)))
        # Clé de signature dérivée des deux secrets : changer l'un d'eux
        # invalide immédiatement toutes les sessions existantes.
        self._cle = hashlib.sha256(
            b"session-v1|" + self._jeton.encode() + b"|" + self._secret_totp.encode()
        ).digest()

        self._verrou = threading.Lock()
        self._dernier_compteur = 0
        self._echecs: list[float] = []
        self._bloque_jusqua = 0.0

    # --- connexion -------------------------------------------------------
    def connexion(self, jeton: str, code: str) -> tuple[str | None, str]:
        """Retourne (jeton_de_session, message). Jeton None = refusé."""
        maintenant = time.time()
        with self._verrou:
            if maintenant < self._bloque_jusqua:
                return None, "Trop d'essais. Réessaie dans quelques minutes."

            jeton_ok = hmac.compare_digest(
                (jeton or "").encode(), self._jeton.encode()
            )
            compteur = self._compteur_valide(str(code or "").strip(), maintenant)

            if jeton_ok and compteur:
                # Le code n'est « consommé » (donc non rejouable) que si les
                # deux facteurs sont bons.
                self._dernier_compteur = compteur
                self._echecs.clear()
                return self._signer(maintenant), "ok"

            self._echecs = [t for t in self._echecs if maintenant - t < FENETRE_ECHECS]
            self._echecs.append(maintenant)
            if len(self._echecs) >= ECHECS_MAX:
                self._bloque_jusqua = maintenant + DUREE_BLOCAGE
                self._echecs.clear()
            # Même message quel que soit le facteur en échec.
            return None, "Identifiants invalides."

    def _compteur_valide(self, code: str, maintenant: float) -> int:
        """Retourne le pas TOTP correspondant au code (±1 pas), ou 0.

        Un pas déjà utilisé ou plus ancien que le dernier utilisé est refusé,
        ce qui interdit de rejouer un code intercepté.
        """
        if len(code) != 6 or not code.isdigit():
            return 0
        courant = int(maintenant // PAS_TOTP)
        trouve = 0
        for c in (courant - 1, courant, courant + 1):
            if hmac.compare_digest(self._totp.generate_otp(c), code) and c > self._dernier_compteur:
                trouve = c
        return trouve

    # --- sessions --------------------------------------------------------
    def _signer(self, maintenant: float) -> str:
        charge = json.dumps({"exp": int(maintenant) + self._duree}, separators=(",", ":"))
        b = base64.urlsafe_b64encode(charge.encode()).rstrip(b"=")
        signature = hmac.new(self._cle, b, hashlib.sha256).digest()
        s = base64.urlsafe_b64encode(signature).rstrip(b"=")
        return f"{b.decode()}.{s.decode()}"

    def session_valide(self, jeton_session: str) -> bool:
        try:
            b, s = jeton_session.split(".", 1)
            attendu = hmac.new(self._cle, b.encode(), hashlib.sha256).digest()
            recu = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
            if not hmac.compare_digest(attendu, recu):
                return False
            charge = json.loads(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)))
            return int(charge["exp"]) > time.time()
        except Exception:
            return False

    @property
    def duree_session(self) -> int:
        return self._duree
