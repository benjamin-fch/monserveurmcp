"""Test de bout en bout du flux OAuth + passkey, sans réseau ni Touch ID.

    python test_oauth_passkey.py

Une passkey logicielle (clé EC P-256 générée à la volée) joue le rôle de
Touch ID : elle signe les défis WebAuthn comme le ferait le Mac.
"""

import base64
import hashlib
import json
import os
import secrets
import tempfile
from urllib.parse import parse_qs, urlparse

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

URL = "http://localhost:8000"


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def deb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --- passkey logicielle ---------------------------------------------------------
cle_privee = ec.generate_private_key(ec.SECP256R1())
nums = cle_privee.public_key().public_numbers()
cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
id_passkey = secrets.token_bytes(16)

os.environ.update(
    {
        "MCP_API_TOKEN": "t" * 40,
        "MCP_TOTP_SECRET": "JBSWY3DPEHPK3PXPJBSWY3DP",
        "PUBLIC_URL": URL,
        "WORKSPACE_DIR": tempfile.mkdtemp(),
        "PASSKEYS": json.dumps([{"id": b64(id_passkey), "cle": b64(cose)}]),
    }
)

from starlette.testclient import TestClient  # noqa: E402

import server  # noqa: E402


def signer_assertion(options: dict, origine: str = URL) -> dict:
    client_data = json.dumps(
        {"type": "webauthn.get", "challenge": options["challenge"], "origin": origine, "crossOrigin": False}
    ).encode()
    # rpIdHash | flags (UP=1, UV=4) | signCount
    auth_data = hashlib.sha256(options["rpId"].encode()).digest() + bytes([0x05]) + (0).to_bytes(4, "big")
    signature = cle_privee.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "id": b64(id_passkey),
        "rawId": b64(id_passkey),
        "type": "public-key",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": b64(client_data),
            "authenticatorData": b64(auth_data),
            "signature": b64(signature),
            "userHandle": b64(b"proprietaire"),
        },
    }


def verifier(condition: bool, message: str) -> None:
    print(("OK   " if condition else "ÉCHEC") + " " + message)
    if not condition:
        raise SystemExit(1)


def appel_mcp(client, jeton: str | None, methode: str, params: dict | None = None):
    entetes = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if jeton:
        entetes["Authorization"] = f"Bearer {jeton}"
    corps = {"jsonrpc": "2.0", "id": 1, "method": methode, "params": params or {}}
    if methode == "initialize":
        corps["params"] = {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        }
    return client.post("/mcp", json=corps, headers=entetes)


with TestClient(server.creer_app(), base_url=URL) as c:
    # 1. Sans jeton : 401 + pointeur vers les métadonnées OAuth
    r = appel_mcp(c, None, "initialize")
    verifier(r.status_code == 401 and "resource_metadata" in r.headers.get("www-authenticate", ""),
             "/mcp sans jeton -> 401 avec resource_metadata")

    r = c.get("/.well-known/oauth-protected-resource/mcp")
    verifier(r.status_code == 200 and r.json()["authorization_servers"], "métadonnées de la ressource protégée")
    r = c.get("/.well-known/oauth-authorization-server")
    meta = r.json()
    verifier(r.status_code == 200 and meta["registration_endpoint"], "métadonnées du serveur d'autorisation")

    # 2. Enregistrement dynamique du client
    r = c.post("/register", json={
        "client_name": "France Student IA",
        "redirect_uris": ["https://client.example/callback"],
        "token_endpoint_auth_method": "client_secret_post",
    })
    verifier(r.status_code == 201, f"enregistrement du client ({r.status_code})")
    client_info = r.json()
    cid, csecret = client_info["client_id"], client_info["client_secret"]
    print(f"     client_id de {len(cid)} caractères")

    # 3. /authorize -> page passkey
    verifieur = b64(secrets.token_bytes(32))
    defi_pkce = b64(hashlib.sha256(verifieur.encode()).digest())
    r = c.get("/authorize", params={
        "response_type": "code", "client_id": cid, "redirect_uri": "https://client.example/callback",
        "code_challenge": defi_pkce, "code_challenge_method": "S256", "state": "xyz",
        "resource": f"{URL}/mcp",
    }, follow_redirects=False)
    verifier(r.status_code == 302 and "/oauth/connexion?r=" in r.headers["location"], "/authorize -> page passkey")
    demande = parse_qs(urlparse(r.headers["location"]).query)["r"][0]
    page = c.get(r.headers["location"])
    verifier(page.status_code == 200 and "France Student IA" in page.text, "page d'autorisation affichée")

    # 4. Passkey : mauvaise origine refusée, bonne origine acceptée
    o = c.post("/passkey/connexion/options").json()
    r = c.post("/passkey/connexion/verifier",
               json={"credential": signer_assertion(o["options"], "https://pirate.example"), "etat": o["etat"], "r": demande})
    verifier(r.status_code == 401, "assertion d'une autre origine refusée")

    o = c.post("/passkey/connexion/options").json()
    assertion = signer_assertion(o["options"])
    r = c.post("/passkey/connexion/verifier", json={"credential": assertion, "etat": o["etat"], "r": demande})
    verifier(r.status_code == 200, f"passkey acceptée ({r.status_code})")
    retour = urlparse(r.json()["redirection"])
    q = parse_qs(retour.query)
    verifier(q.get("state") == ["xyz"] and "code" in q, "redirection vers le client avec code + state")

    r = c.post("/passkey/connexion/verifier", json={"credential": assertion, "etat": o["etat"], "r": demande})
    verifier(r.status_code == 401, "rejeu du même défi refusé")

    # 5. Code -> jetons (PKCE)
    jeton_req = {"grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": "https://client.example/callback",
                 "client_id": cid, "client_secret": csecret, "resource": f"{URL}/mcp"}
    r = c.post("/token", data={**jeton_req, "code_verifier": "mauvais" * 7})
    verifier(r.status_code == 400, "mauvais code_verifier refusé")
    r = c.post("/token", data={**jeton_req, "code_verifier": verifieur})
    verifier(r.status_code == 200, f"échange du code ({r.status_code} {r.text[:120]})")
    jetons = r.json()
    r = c.post("/token", data={**jeton_req, "code_verifier": verifieur})
    verifier(r.status_code == 400, "réutilisation du code refusée")

    # 6. Accès MCP avec le jeton
    r = appel_mcp(c, jetons["access_token"], "initialize")
    verifier(r.status_code == 200, f"initialize avec jeton OAuth ({r.status_code})")
    r = appel_mcp(c, jetons["access_token"], "tools/list")
    noms = [t["name"] for t in r.json()["result"]["tools"]]
    verifier("lire_guide" in noms and "ecrire_fichier" in noms, f"{len(noms)} outils listés")
    r = appel_mcp(c, jetons["access_token"] + "x", "tools/list")
    verifier(r.status_code == 401, "jeton altéré refusé")

    # 7. Renouvellement
    r = c.post("/token", data={"grant_type": "refresh_token", "refresh_token": jetons["refresh_token"],
                               "client_id": cid, "client_secret": csecret})
    verifier(r.status_code == 200 and r.json()["access_token"], "renouvellement du jeton")
    verifier(appel_mcp(c, r.json()["access_token"], "tools/list").status_code == 200, "nouveau jeton accepté")

    # 8. Client public (sans secret), comme beaucoup de clients MCP
    r = c.post("/register", json={"client_name": "Public", "redirect_uris": ["http://localhost:9999/cb"],
                                  "token_endpoint_auth_method": "none"})
    verifier(r.status_code == 201 and not r.json().get("client_secret"), "client public enregistré")

    # 9. Archive et SSE protégés
    verifier(c.get("/workspace.zip").status_code == 401, "/workspace.zip sans jeton -> 401")
    verifier(c.get("/workspace.zip", headers={"Authorization": f"Bearer {jetons['access_token']}"}).status_code == 200,
             "/workspace.zip avec jeton OAuth")
    verifier(c.get("/sse").status_code == 401, "/sse sans jeton -> 401")
    verifier(c.get("/health").status_code == 200, "/health public")
    verifier(c.get("/passkey/installer").status_code == 200, "page d'installation servie")
    r = c.post("/passkey/installer/options", json={"token": "faux", "code": "000000"})
    verifier(r.status_code == 401, "installation refusée sans double authentification")

    # 10. Installation d'une nouvelle passkey (double authentification + WebAuthn)
    import pyotp

    code = pyotp.TOTP(os.environ["MCP_TOTP_SECRET"]).now()
    r = c.post("/passkey/installer/options", json={"token": os.environ["MCP_API_TOKEN"], "code": code})
    verifier(r.status_code == 200, f"options d'installation ({r.status_code})")
    o = r.json()
    nouvel_id = secrets.token_bytes(16)
    client_data = json.dumps({"type": "webauthn.create", "challenge": o["options"]["challenge"],
                              "origin": URL, "crossOrigin": False}).encode()
    auth_data = (hashlib.sha256(o["options"]["rp"]["id"].encode()).digest() + bytes([0x45]) + (0).to_bytes(4, "big")
                 + bytes(16) + len(nouvel_id).to_bytes(2, "big") + nouvel_id + cose)
    attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
    r = c.post("/passkey/installer/verifier", json={"etat": o["etat"], "nom": "Test", "credential": {
        "id": b64(nouvel_id), "rawId": b64(nouvel_id), "type": "public-key", "clientExtensionResults": {},
        "response": {"clientDataJSON": b64(client_data), "attestationObject": b64(attestation), "transports": ["internal"]}}})
    verifier(r.status_code == 200, f"passkey installée ({r.status_code})")
    liste = json.loads(r.json()["valeur"])
    verifier(len(liste) == 2 and liste[1]["nom"] == "Test", "valeur PASSKEYS à coller contient les 2 passkeys")

    # 11. Ancienne session 2FA (scripts locaux) toujours acceptée
    session, _ = server.auth.connexion(os.environ["MCP_API_TOKEN"], pyotp.TOTP(os.environ["MCP_TOTP_SECRET"]).at(
        __import__("time").time() + 30))
    verifier(session is not None and appel_mcp(c, session, "tools/list").status_code == 200,
             "jeton de session 2FA (login.py) accepté sur /mcp")

print("\nTous les tests passent.")
