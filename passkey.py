"""Connexion par passkey (Touch ID, Face ID, clé de sécurité) — WebAuthn.

Pages servies par le serveur :
  /passkey/installer   enregistre une passkey (une fois par appareil). Protégée
                       par l'ancienne double authentification (jeton + code TOTP).
  /oauth/connexion     page d'autorisation OAuth : un geste Touch ID / Face ID
                       donne l'accès à l'IA qui la demande.

Les passkeys enregistrées vivent dans la variable d'environnement PASSKEYS
(liste JSON de clés publiques, rien de secret) : elles survivent aux
redémarrages de Render sans disque persistant.
"""

import html
import json
import os
import secrets
from urllib.parse import urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from oauth import FournisseurOAuth, UsageUnique, hote_redirection

# Pages sensibles : jamais affichées dans un cadre (anti-clickjacking).
ENTETES_HTML = {
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def reponse_html(contenu: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(contenu, status_code=status_code, headers=ENTETES_HTML)

DUREE_DEFI = 300
NOM_SERVICE = "Serveur IA de Benjamin"


def passkeys_enregistrees() -> list[dict]:
    brut = os.environ.get("PASSKEYS", "").strip()
    if not brut:
        return []
    try:
        liste = json.loads(brut)
        return [p for p in liste if isinstance(p, dict) and p.get("id") and p.get("cle")]
    except json.JSONDecodeError:
        return []


class Passkeys:
    def __init__(self, fournisseur: FournisseurOAuth, auth) -> None:
        self.fournisseur = fournisseur
        self.auth = auth  # double authentification, pour l'installation
        self.signataire = fournisseur.signataire
        self.defis_utilises = UsageUnique()
        url = urlparse(fournisseur.url_publique)
        self.rp_id = url.hostname or "localhost"
        self.origine = f"{url.scheme}://{url.netloc}"

    # --- défis signés (aucun état serveur) --------------------------------
    def _nouveau_defi(self, but: str) -> tuple[bytes, str]:
        defi = secrets.token_bytes(32)
        etat = self.signataire.signer("defi", {"ch": bytes_to_base64url(defi), "but": but}, DUREE_DEFI)
        return defi, etat

    def _lire_defi(self, etat: str, but: str) -> bytes | None:
        d = self.signataire.verifier("defi", etat or "")
        if d is None or d["but"] != but or not self.defis_utilises.consommer(d["ch"], d["exp"]):
            return None
        return base64url_to_bytes(d["ch"])

    # --- installation d'une passkey ----------------------------------------
    async def page_installer(self, request: Request) -> Response:
        return reponse_html(page_installation(len(passkeys_enregistrees())))

    async def installer_options(self, request: Request) -> Response:
        try:
            donnees = await request.json()
        except Exception:
            return JSONResponse({"erreur": "Requête invalide."}, status_code=400)
        session, message = self.auth.connexion(str(donnees.get("token", "")), str(donnees.get("code", "")))
        if session is None:
            return JSONResponse({"erreur": message}, status_code=401)

        defi, etat = self._nouveau_defi("installer")
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=NOM_SERVICE,
            user_name="proprietaire",
            user_display_name="Propriétaire du serveur",
            user_id=b"proprietaire",
            challenge=defi,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["id"])) for p in passkeys_enregistrees()
            ],
        )
        return JSONResponse({"options": json.loads(options_to_json(options)), "etat": etat})

    async def installer_verifier(self, request: Request) -> Response:
        try:
            donnees = await request.json()
            defi = self._lire_defi(donnees.get("etat", ""), "installer")
            if defi is None:
                return JSONResponse({"erreur": "Défi expiré, recommence."}, status_code=400)
            resultat = verify_registration_response(
                credential=donnees["credential"],
                expected_challenge=defi,
                expected_rp_id=self.rp_id,
                expected_origin=self.origine,
                require_user_verification=True,
            )
        except Exception:
            return JSONResponse({"erreur": "Passkey refusée."}, status_code=400)

        nouvelle = {
            "id": bytes_to_base64url(resultat.credential_id),
            "cle": bytes_to_base64url(resultat.credential_public_key),
            "nom": str(donnees.get("nom", ""))[:40] or "appareil",
        }
        liste = passkeys_enregistrees() + [nouvelle]
        return JSONResponse({"valeur": json.dumps(liste, separators=(",", ":"))})

    # --- connexion (page d'autorisation OAuth) ------------------------------
    async def page_connexion(self, request: Request) -> Response:
        demande = self.fournisseur.lire_demande(request.query_params.get("r", ""))
        if demande is None:
            return reponse_html(page_message("Lien expiré", "Relance la connexion depuis ton IA."), 400)
        return reponse_html(
            page_autorisation(demande["nom"], hote_redirection(demande["ru"]), bool(passkeys_enregistrees()))
        )

    async def connexion_options(self, request: Request) -> Response:
        cles = passkeys_enregistrees()
        if not cles:
            return JSONResponse({"erreur": "Aucune passkey enregistrée."}, status_code=400)
        defi, etat = self._nouveau_defi("connexion")
        options = generate_authentication_options(
            rp_id=self.rp_id,
            challenge=defi,
            allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["id"])) for p in cles],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return JSONResponse({"options": json.loads(options_to_json(options)), "etat": etat})

    async def connexion_verifier(self, request: Request) -> Response:
        refus = JSONResponse({"erreur": "Connexion refusée."}, status_code=401)
        try:
            donnees = await request.json()
        except Exception:
            return refus
        demande = self.fournisseur.lire_demande(donnees.get("r", ""))
        defi = self._lire_defi(donnees.get("etat", ""), "connexion")
        credential = donnees.get("credential") or {}
        cle = next((p for p in passkeys_enregistrees() if p["id"] == credential.get("id")), None)
        if demande is None or defi is None or cle is None:
            return refus
        try:
            verify_authentication_response(
                credential=credential,
                expected_challenge=defi,
                expected_rp_id=self.rp_id,
                expected_origin=self.origine,
                credential_public_key=base64url_to_bytes(cle["cle"]),
                credential_current_sign_count=0,
                require_user_verification=True,
            )
            redirection = self.fournisseur.accorder(demande)
        except Exception:
            return refus
        return JSONResponse({"redirection": redirection})

    def enregistrer(self, mcp) -> None:
        routes = [
            ("/passkey/installer", ["GET"], self.page_installer),
            ("/passkey/installer/options", ["POST"], self.installer_options),
            ("/passkey/installer/verifier", ["POST"], self.installer_verifier),
            ("/oauth/connexion", ["GET"], self.page_connexion),
            ("/passkey/connexion/options", ["POST"], self.connexion_options),
            ("/passkey/connexion/verifier", ["POST"], self.connexion_verifier),
        ]
        for chemin, methodes, fonction in routes:
            mcp.custom_route(chemin, methods=methodes)(fonction)


# --- pages HTML ---------------------------------------------------------------

STYLE = """
:root{--fond:#f6f7f9;--carte:#fff;--texte:#14181f;--doux:#5b6472;--accent:#0f766e;--bord:#e3e6eb;--erreur:#b42318}
@media (prefers-color-scheme:dark){:root{--fond:#0f1418;--carte:#172026;--texte:#e8edf1;--doux:#9aa6b2;--accent:#5eead4;--bord:#26323b;--erreur:#f97066}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--fond);
color:var(--texte);font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;padding:16px}
main{width:100%;max-width:420px;background:var(--carte);border:1px solid var(--bord);border-radius:16px;padding:28px}
h1{font-size:1.3rem;margin:0 0 8px}p{color:var(--doux);margin:0 0 18px}
button{width:100%;padding:13px;border:0;border-radius:10px;background:var(--accent);color:var(--fond);
font:600 1rem inherit;cursor:pointer}button:disabled{opacity:.5;cursor:default}
label{display:block;font-size:.9rem;margin:0 0 4px}input,textarea{width:100%;padding:11px;margin:0 0 14px;border:1px solid var(--bord);
border-radius:10px;background:var(--fond);color:var(--texte);font:inherit}textarea{font:13px ui-monospace,monospace;height:110px}
#statut{min-height:1.5em;margin:14px 0 0;color:var(--doux)}#statut.erreur{color:var(--erreur)}
code{font:13px ui-monospace,monospace}
"""

SCRIPT_COMMUN = """
const b64 = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const vers64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
function statut(t, err){ const s=document.getElementById('statut'); s.textContent=t; s.className=err?'erreur':''; }
async function post(url, corps){
  const r = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(corps)});
  const j = await r.json().catch(()=>({erreur:'Réponse invalide du serveur.'}));
  if(!r.ok) throw new Error(j.erreur || 'Erreur ' + r.status);
  return j;
}
function enJSON(c){
  if (c.toJSON) { try { return c.toJSON(); } catch(e){} }
  const r = c.response, out = {id:c.id, rawId:vers64(c.rawId), type:c.type, clientExtensionResults:c.getClientExtensionResults(), response:{clientDataJSON:vers64(r.clientDataJSON)}};
  if (r.attestationObject) { out.response.attestationObject = vers64(r.attestationObject); out.response.transports = r.getTransports ? r.getTransports() : []; }
  if (r.authenticatorData) { out.response.authenticatorData = vers64(r.authenticatorData); out.response.signature = vers64(r.signature);
    if (r.userHandle) out.response.userHandle = vers64(r.userHandle); }
  return out;
}
function optionsCreation(o){
  if (PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(o);
  return {...o, challenge:b64(o.challenge), user:{...o.user, id:b64(o.user.id)}, excludeCredentials:(o.excludeCredentials||[]).map(c=>({...c,id:b64(c.id)}))};
}
function optionsConnexion(o){
  if (PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(o);
  return {...o, challenge:b64(o.challenge), allowCredentials:(o.allowCredentials||[]).map(c=>({...c,id:b64(c.id)}))};
}
"""


def _page(titre: str, corps: str, script: str = "") -> str:
    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(titre)}</title>
<style>{STYLE}</style></head><body><main>{corps}</main>
<script>{SCRIPT_COMMUN}{script}</script></body></html>"""


def page_message(titre: str, texte: str) -> str:
    return _page(titre, f"<h1>{html.escape(titre)}</h1><p>{html.escape(texte)}</p>")


def page_autorisation(nom_client: str, hote_retour: str, a_des_passkeys: bool) -> str:
    nom = html.escape(nom_client)
    hote = html.escape(hote_retour)
    if not a_des_passkeys:
        return page_message(
            "Aucune passkey", "Enregistre d'abord une passkey sur /passkey/installer, puis relance la connexion."
        )
    corps = f"""<h1>Autoriser {nom}</h1>
<p><strong>{nom}</strong> demande l'accès à tes tâches et à ton espace de fichiers.</p>
<p>L'accès sera envoyé à <strong>{hote}</strong>. Si tu n'as pas lancé cette connexion toi-même,
ou si ce site ne correspond pas à ton IA (claude.ai, France Student…), ferme cette page.</p>
<button id="ok">Se connecter avec Touch ID / Face ID</button><div id="statut"></div>"""
    script = """
document.getElementById('ok').onclick = async (e) => {
  e.target.disabled = true; statut('En attente de la passkey…');
  try {
    const r = new URLSearchParams(location.search).get('r');
    const {options, etat} = await post('/passkey/connexion/options', {});
    const cred = await navigator.credentials.get({publicKey: optionsConnexion(options)});
    const {redirection} = await post('/passkey/connexion/verifier', {credential: enJSON(cred), etat, r});
    const cible = new URL(redirection);
    if (!['https:', 'http:'].includes(cible.protocol)) throw new Error('Adresse de retour refusée.');
    statut('Accès accordé, retour à l\\'application…');
    location.href = cible.href;
  } catch (err) { statut(err.message || 'Connexion annulée.', true); e.target.disabled = false; }
};"""
    return _page(f"Autoriser {nom_client}", corps, script)


def page_installation(nombre: int) -> str:
    deja = f"{nombre} passkey(s) déjà enregistrée(s)." if nombre else "Aucune passkey enregistrée pour l'instant."
    corps = f"""<h1>Enregistrer une passkey</h1>
<p>{deja} Confirme avec l'ancienne double authentification, puis Touch ID / Face ID.</p>
<form id="f"><label for="token">Jeton secret (MCP_API_TOKEN)</label>
<input id="token" type="password" autocomplete="off" required>
<label for="code">Code à 6 chiffres</label>
<input id="code" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" autocomplete="one-time-code" required>
<label for="nom">Nom de l'appareil</label><input id="nom" value="Mac" maxlength="40">
<button id="ok">Créer la passkey</button></form><div id="statut"></div>
<div id="resultat" hidden><p>Passkey créée. Sur Render, remplace la variable <code>PASSKEYS</code> par :</p>
<textarea id="valeur" readonly></textarea><button id="copier" type="button">Copier</button></div>"""
    script = """
document.getElementById('f').onsubmit = async (e) => {
  e.preventDefault(); const b = document.getElementById('ok'); b.disabled = true; statut('Vérification…');
  try {
    const {options, etat} = await post('/passkey/installer/options',
      {token: document.getElementById('token').value, code: document.getElementById('code').value});
    statut('Pose ton doigt sur Touch ID…');
    const cred = await navigator.credentials.create({publicKey: optionsCreation(options)});
    const {valeur} = await post('/passkey/installer/verifier',
      {credential: enJSON(cred), etat, nom: document.getElementById('nom').value});
    document.getElementById('f').hidden = true; document.getElementById('resultat').hidden = false;
    document.getElementById('valeur').value = valeur; statut('');
  } catch (err) { statut(err.message || 'Annulé.', true); b.disabled = false; }
};
document.getElementById('copier').onclick = () => {
  navigator.clipboard.writeText(document.getElementById('valeur').value); statut('Copié.');
};"""
    return _page("Enregistrer une passkey", corps, script)
