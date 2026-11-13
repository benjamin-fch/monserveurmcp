"""Génère les deux secrets de la double authentification.

À lancer UNE FOIS, en local, sur ton ordinateur :
    python setup_2fa.py

Le script affiche :
  - MCP_API_TOKEN et MCP_TOTP_SECRET : à copier dans les variables
    d'environnement de Render (Environment > Add Environment Variable) ;
  - un lien otpauth:// : à ajouter dans ton application d'authentification
    (Google Authenticator, Authy, 1Password...) en scannant un QR code ou en
    saisissant la clé manuellement.

Ne colle jamais ces secrets dans un chat, un dépôt Git ou un fichier public.
"""

import secrets

import pyotp


def main() -> None:
    jeton = secrets.token_urlsafe(32)
    secret_totp = pyotp.random_base32()
    uri = pyotp.TOTP(secret_totp).provisioning_uri(
        name="serveur-mcp", issuer_name="Serveur MCP"
    )

    print("=" * 64)
    print("1) Variables à ajouter sur Render (Environment) :")
    print("=" * 64)
    print(f"MCP_API_TOKEN={jeton}")
    print(f"MCP_TOTP_SECRET={secret_totp}")
    print()
    print("=" * 64)
    print("2) Application d'authentification :")
    print("=" * 64)
    print("Dans l'application : ajouter un compte > saisir une clé de configuration,")
    print(f"type « basé sur l'heure », clé : {secret_totp}")
    print(f"(ou lien otpauth pour un générateur de QR code : {uri})")
    print()
    print("3) Sur ton ordinateur, fichier .env à côté de login.py (déjà ignoré par Git) :")
    print("MCP_URL=https://TON-SERVICE.onrender.com")
    print(f"MCP_API_TOKEN={jeton}")


if __name__ == "__main__":
    main()
