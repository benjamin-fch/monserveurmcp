# Vérificateur de liens — sous-projet du serveur MCP

**Objectif** : vérifier si un lien est une arnaque, du phishing ou un piège **sans
l'ouvrir sur le téléphone ou l'ordinateur de Benj**. C'est le serveur (Render) qui
va voir le site à sa place.

**État** : terminé et testé localement (15 tests). Exposé aux IA (Claude, France
Student IA, VS Code) par l'outil MCP `analyser_lien` défini dans `../server.py`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `analyse_lien.py` | Toute l'analyse : récupération sécurisée, heuristiques, services externes, verdict. Bibliothèque standard uniquement. |
| `test_analyse_lien.py` | Tests sans Internet : un faux site de phishing tourne en local. |
| `../guides/04-verifier-un-lien.md` | Mode d'emploi pour les IA (règles, exemple de réponse). |

## Comment ça marche

1. **Adresse** : imitation de marques (Ameli, impots, La Poste, banques, PayPal…),
   fautes de frappe volontaires (`paypa1`), lettres d'autres alphabets, faux « gouv »,
   extension douteuse, adresse IP, lien raccourci, adresse cachée dans le lien.
2. **Récupération passive** (jamais de JavaScript exécuté, rien d'installé) : suit les
   redirections en bloquant toute adresse interne à chaque étape, lit 1,5 Mo / 20 s max,
   se fait passer pour un iPhone par défaut.
3. **Page** : demande de carte bancaire / code SMS / IBAN, formulaire envoyé ailleurs,
   robot Telegram ou webhook Discord, ton pressant, téléchargement d'APK ou de profil
   iPhone, code brouillé, certificat invalide.
4. **Âge du domaine** via RDAP (annuaire officiel des noms de domaine).
5. **Services externes optionnels** (clés dans les variables d'environnement de Render) :
   `URLSCAN_API_KEY` (navigateur isolé + capture d'écran), `GOOGLE_SAFE_BROWSING_KEY`,
   `VIRUSTOTAL_API_KEY`.
6. **Verdict** : score de 0 à 100 → 🔴 DANGEREUX (≥ 50) / 🟠 SUSPECT (≥ 20) /
   🟢 AUCUN SIGNAL D'ALERTE, avec les raisons et un conseil.

## Tester

Depuis la racine du dépôt :

```
python -m unittest verificateur_liens.test_analyse_lien -v
python -m verificateur_liens.analyse_lien "https://lien-suspect" --sans-scan
```

## Pistes d'amélioration

- Compléter la liste `MARQUES` quand une nouvelle arnaque imite une marque absente.
- Les résultats sont gardés 10 min en mémoire (`DUREE_CACHE`) : un même lien n'est
  pas réanalysé pendant ce temps.
