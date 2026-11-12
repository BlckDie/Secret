#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
encode.py — Générateur du « COFFRE-ZERO », chasse au trésor cryptographique.

Ce script fabrique TOUT le jeu à partir d'un secret :
  * index.html            le coffre (ciphertext AES-256-GCM + énigme cachée)
  * indices/vitrail_N.png les vitraux (un seul porte le message stéganographié)
  * indices/carnet.txt    le carnet du gardien (sert à l'étape finale en "extreme")
  * indices/note.txt      un leurre
  * SOLUTION.md           la soluce complète (NE PAS déployer)

Chaque exécution tire un nouveau sel, un nouvel IV et (en "extreme") une
nouvelle phrase de passe : relancer le script = nouvelle partie.

Le secret n'est écrit NULLE PART en clair : il n'existe que chiffré dans
index.html. Il est affiché une seule fois dans le terminal.

Usage :
    python encode.py                         # génère un secret aléatoire
    python encode.py --secret "ma phrase"    # utilise votre phrase
    python encode.py --difficulte moyen      # écrase la constante ci-dessous

Dépendances : Pillow, cryptography  (pip install pillow cryptography)
"""

# ─────────────────────────────────────────────────────────────────────────────
DIFFICULTE = "extreme"          # "moyen" (~30 min) ou "extreme"
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import base64
import json
import os
import re
import secrets
import sys
import unicodedata
from pathlib import Path

from PIL import Image, ImageDraw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ICI = Path(__file__).resolve().parent
INDICES = ICI / "indices"

ITERATIONS = 600_000            # PBKDF2-SHA256 (≥ 300 000 exigé)
TITRE = "COFFRE-ZERO"           # titre de la page = clé XOR de la stégo (extreme)
CLE_VIGENERE = "OUROBOROS"      # lue en acrostiche dans le commentaire HTML
NB_VITRAUX = 12
VITRAIL_EXTREME = len(CLE_VIGENERE)   # « le numéro égale le nombre de lettres de sa clé »
VITRAIL_MOYEN = 3
ZW0, ZW1 = "​", "‌"   # ZERO WIDTH SPACE = 0, ZERO WIDTH NON-JOINER = 1

RNG = secrets.SystemRandom()    # aléa cryptographique pour tous les tirages


# ═════════════════════════════════════════════════════════════════════════════
# Briques cryptographiques / d'encodage
# ═════════════════════════════════════════════════════════════════════════════

def normaliser(phrase: str) -> str:
    """Même normalisation que le JavaScript de la page : minuscules, sans
    accents, espaces -> tirets, uniquement [a-z0-9-]."""
    s = unicodedata.normalize("NFD", phrase)
    s = re.sub("[̀-ͯ]", "", s).lower().strip()
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"[^a-z0-9-]", "", s)
    return re.sub(r"-+", "-", s)


def chiffrer_secret(secret: str, phrase: str) -> dict:
    """AES-256-GCM, clé = PBKDF2-SHA256(phrase normalisée, sel aléatoire)."""
    sel = os.urandom(16)
    iv = os.urandom(12)
    cle = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sel,
                     iterations=ITERATIONS).derive(normaliser(phrase).encode())
    ct = AESGCM(cle).encrypt(iv, secret.encode("utf-8"), None)  # ct || tag
    b64 = lambda b: base64.b64encode(b).decode()
    return {"v": 1, "kdf": "PBKDF2-SHA256", "iter": ITERATIONS,
            "sel": b64(sel), "iv": b64(iv), "ct": b64(ct)}


def dechiffrer_secret(coffre: dict, phrase: str) -> str:
    d = base64.b64decode
    cle = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=d(coffre["sel"]),
                     iterations=coffre["iter"]).derive(normaliser(phrase).encode())
    return AESGCM(cle).decrypt(d(coffre["iv"]), d(coffre["ct"]), None).decode()


def vigenere(texte: str, cle: str, sens: int = 1) -> str:
    """Vigenère sur A-Z uniquement ; les autres caractères passent tels quels
    et ne font pas avancer la clé. sens=+1 chiffre, -1 déchiffre."""
    out, j = [], 0
    for c in texte:
        if "A" <= c <= "Z":
            k = ord(cle[j % len(cle)]) - 65
            out.append(chr((ord(c) - 65 + sens * k) % 26 + 65))
            j += 1
        else:
            out.append(c)
    return "".join(out)


def cesar(texte: str, decalage: int) -> str:
    return vigenere(texte, chr(65 + decalage % 26))


def octets_vers_zw(data: bytes) -> str:
    """Chaque bit devient un caractère de largeur nulle (MSB d'abord)."""
    return "".join(ZW1 if (b >> (7 - i)) & 1 else ZW0 for b in data for i in range(8))


def zw_vers_octets(texte: str) -> bytes:
    bits = "".join("0" if c == ZW0 else "1" for c in texte if c in (ZW0, ZW1))
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))


def disperser(visible: str, invisible: str) -> str:
    """Répartit les caractères invisibles « entre les lettres » du texte."""
    trous = len(visible) - 1
    pas = -(-len(invisible) // trous)          # division plafond
    morceaux = [invisible[i:i + pas] for i in range(0, len(invisible), pas)]
    out = []
    for i, c in enumerate(visible):
        out.append(c)
        if i < len(morceaux):
            out.append(morceaux[i])
    return "".join(out)


def xor(data: bytes, cle: bytes) -> bytes:
    return bytes(b ^ cle[i % len(cle)] for i, b in enumerate(data))


# ── Stéganographie LSB ───────────────────────────────────────────────────────

CANAUX = {"R": 0, "G": 1, "B": 2}


def cacher_lsb(img: Image.Image, charge: bytes, canaux: str) -> Image.Image:
    """Écrit [longueur 4 octets big-endian][charge] dans le bit de poids faible
    des canaux donnés (ex. "GB"), pixel par pixel, gauche→droite, haut→bas."""
    data = len(charge).to_bytes(4, "big") + charge
    bits = [(b >> (7 - i)) & 1 for b in data for i in range(8)]
    idx = [CANAUX[c] for c in canaux]
    px = list(img.getdata())
    if len(bits) > len(px) * len(idx):
        raise ValueError("Image trop petite pour la charge")
    k = 0
    for p in range(len(px)):
        if k >= len(bits):
            break
        v = list(px[p])
        for c in idx:
            if k < len(bits):
                v[c] = (v[c] & 0xFE) | bits[k]
                k += 1
        px[p] = tuple(v)
    out = Image.new("RGB", img.size)
    out.putdata(px)
    return out


def lire_lsb(img: Image.Image, canaux: str) -> bytes:
    idx = [CANAUX[c] for c in canaux]
    bits = [px[c] & 1 for px in img.convert("RGB").getdata() for c in idx]
    octets = bytes(int("".join(map(str, bits[i:i + 8])), 2)
                   for i in range(0, len(bits) - 7, 8))
    n = int.from_bytes(octets[:4], "big")
    return octets[4:4 + n]


def fabriquer_vitrail(taille: int = 256) -> Image.Image:
    """Un « vitrail » procédural : éclats colorés sertis de plomb + bruit.
    Le bruit rend les bits de poids faible aléatoires sur TOUTES les images,
    leurres compris : rien ne distingue le porteur à l'œil ni à l'histogramme."""
    img = Image.new("RGB", (taille, taille), (10, 8, 20))
    d = ImageDraw.Draw(img)
    palette = [(RNG.randrange(40, 230), RNG.randrange(20, 200), RNG.randrange(60, 255))
               for _ in range(6)]
    for _ in range(55):
        cx, cy = RNG.randrange(taille), RNG.randrange(taille)
        pts = [(cx + RNG.randrange(-60, 60), cy + RNG.randrange(-60, 60)) for _ in range(3)]
        d.polygon(pts, fill=RNG.choice(palette), outline=(15, 12, 18), width=3)
    c = taille // 2
    for r in range(c, 0, -RNG.randrange(18, 30)):        # rosace
        d.ellipse((c - r, c - r, c + r, c + r), outline=(15, 12, 18), width=2)
    brut = bytearray(img.tobytes())
    bruit = os.urandom(len(brut))
    for i in range(len(brut)):
        brut[i] = max(0, min(255, brut[i] + (bruit[i] % 17) - 8))
    return Image.frombytes("RGB", img.size, bytes(brut))


def romain(n: int) -> str:
    table = [(10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I")]
    out = ""
    for v, s in table:
        while n >= v:
            out += s
            n -= v
    return out


def mots_de(ligne: str) -> list:
    """Un mot = suite maximale de lettres (apostrophes, tirets, ponctuation séparent)."""
    return re.findall(r"[^\W\d_]+", ligne)


# ═════════════════════════════════════════════════════════════════════════════
# Contenus du jeu
# ═════════════════════════════════════════════════════════════════════════════

CARNET = """CARNET DU GARDIEN — tenu à la lueur d'une lampe qui fume trop
Le premier soir, la neige a recouvert les marches de l'observatoire.
J'ai compté les cloches du village : onze, puis un silence immense.
Le serpent de cuivre au-dessus de la porte semblait respirer lentement.
Personne ne vient jamais ici, sauf le facteur et parfois un renard.
Ce matin, une corneille a frappé trois fois contre le vitrail nord.
J'ai huilé le verrou principal avec la graisse de la lanterne.
Les cartes du ciel sont rangées dans le tiroir aux boussoles cassées.
Mon grand-père disait que le silence pèse plus lourd que le plomb.
Il gardait une clé d'argent cousue dans la doublure de son manteau.
La rivière gèle par plaques, comme un miroir que l'on aurait brisé.
J'entends parfois chanter quelqu'un sous le plancher de la cave.
Sans doute le vent qui s'engouffre dans les vieilles canalisations.
Hier, j'ai trouvé une plume bleue posée sur le registre ouvert.
Le registre mentionne un voyageur venu de Prague en mille neuf cent douze.
Il cherchait, disait-il, le chiffre qui dort sous les couleurs.
Je lui ai servi du thé noir et des biscuits à la cannelle.
Il a dessiné un cercle, puis un serpent qui mordait sa propre queue.
Au matin, il était parti, laissant ses bottes devant la cheminée.
Depuis, je dors avec la lampe allumée et la fenêtre entrouverte.
Les étoiles de février ont une couleur de lait tourné.
Je soupçonne la comète d'avoir dévié pendant la nuit de mardi.
Le télescope tremble quand passe le train de marchandises.
J'ai réparé l'horloge du hall ; elle avance encore de quatre minutes.
Un chat gris s'est installé dans la bibliothèque, près des atlas.
Il ne quitte jamais l'étagère des livres interdits.
Ce soir, la brume monte du lac et efface les sapins un à un.
Si quelqu'un lit ceci, qu'il sache que le coffre ne ment jamais.
Il faut seulement savoir regarder là où rien ne semble écrit.
Fin du premier carnet. Le suivant est caché ailleurs.
"""

SERMENT = ("Je jure de garder le coffre tant que le serpent dormira, de ne rien "
           "dire aux curieux, de ne rien montrer aux pressés, et de n'ouvrir qu'à "
           "celui qui saura lire ce qui ne s'écrit pas.")

COMMENTAIRE_EXTREME = """<!--
  Le gardien a laissé ces vers avant de partir. Lis-les debout, pas couché.

  Oublie ce que tes yeux te montrent ;
  Un serment n'est jamais tout à fait plein de ses seules lettres.
  Regarde entre elles, là où rien ne prend de place,
  Où le zéro est un espace et le un refuse de joindre.
  Brise d'abord le miroir,
  Ouvre ensuite les soixante-quatre portes,
  Rends enfin au serpent ce que sa clé lui a pris.
  Ô toi qui cherches : la clé se lit à la verticale.
  Sans elle, rien ne tourne.
-->"""

COMMENTAIRE_MOYEN = """<!--
  Gardien distrait : j'ai glissé un murmure dans l'attribut data-murmure du coffre.
  Ouvre d'abord les soixante-quatre portes, puis fais reculer chaque lettre de trois pas.
-->"""

M2_EXTREME = (
    "BIEN JOUE. LE SERPENT DORT DANS LE DOSSIER INDICES, DANS LE VITRAIL DONT LE "
    "NUMERO EGALE LE NOMBRE DE LETTRES DE SA CLE. LIS LE BIT DE POIDS FAIBLE DU "
    "VERT PUIS DU BLEU DE CHAQUE PIXEL, DE GAUCHE A DROITE ET DE HAUT EN BAS. "
    "ASSEMBLE LES BITS PAR HUIT, LE PLUS FORT EN PREMIER. LES QUATRE PREMIERS "
    "OCTETS, GROS BOUTIENS, DONNENT LA LONGUEUR DU MESSAGE. CHAQUE OCTET QUI SUIT "
    "EST MASQUE PAR UN OU EXCLUSIF AVEC LE TITRE DE CETTE PAGE, REPETE AUTANT QUE "
    "NECESSAIRE.")

M2_MOYEN = (
    f"OUVRE INDICES/VITRAIL_{VITRAIL_MOYEN}.PNG. LIS LE BIT DE POIDS FAIBLE DU ROUGE "
    "DE CHAQUE PIXEL, DE GAUCHE A DROITE ET DE HAUT EN BAS, PAR GROUPES DE HUIT, LE "
    "PLUS FORT EN PREMIER. LES QUATRE PREMIERS OCTETS (GROS BOUTIENS) DONNENT LA "
    "LONGUEUR, LE RESTE EST LE MESSAGE.")

NOTE_LEURRE = """Note retrouvée sous la porte :

    « Le mot de passe, c'est le nom du chat. »

(Le gardien n'a jamais nommé le chat.)
"""


def secret_aleatoire() -> str:
    lieux = ["le pont des Soupirs", "la troisième arche", "le phare éteint",
             "la gare de Pripyat", "le vieux moulin", "la fontaine sèche"]
    mots = ["CENDRE", "LUCIOLE", "ALBATROS", "MERIDIEN", "OBSIDIENNE", "ZEPHYR"]
    return (f"Le corbeau n°{RNG.randrange(1000, 9999)} attend sous {RNG.choice(lieux)} "
            f"à {RNG.randrange(0, 24)}h{RNG.randrange(0, 60):02d}. "
            f"Mot d'ordre : {RNG.choice(mots)}-{secrets.token_hex(3).upper()}.")


def choisir_phrase_extreme():
    """Tire 6 mots (≥ 4 lettres) sur 6 lignes distinctes du carnet."""
    lignes = CARNET.splitlines()
    candidates = [i for i, l in enumerate(lignes, 1) if any(len(m) >= 4 for m in mots_de(l))]
    choix = RNG.sample(candidates, 6)
    coords, mots = [], []
    for n in choix:
        ms = mots_de(lignes[n - 1])
        positions = [i for i, m in enumerate(ms, 1) if len(m) >= 4]
        p = RNG.choice(positions)
        coords.append((n, p))
        mots.append(normaliser(ms[p - 1]))
    phrase = "-".join(mots) + f"-{sum(n for n, _ in coords)}"
    return phrase, coords, mots


# ═════════════════════════════════════════════════════════════════════════════
# Page HTML
# ═════════════════════════════════════════════════════════════════════════════

GABARIT = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITRE__</title>
<meta name="cle" content="__LEURRE_META__">
<script>
"use strict";
/* ── Réglage de la partie (généré par encode.py) ─────────────────────── */
const DIFFICULTE = "__DIFFICULTE__";

/* Le coffre : UNIQUEMENT le ciphertext, le sel et l'IV (+ paramètres KDF).
   Ni la phrase de passe ni la clé ne sont présentes dans cette page. */
const COFFRE = __COFFRE__;

/* Même normalisation que encode.py : minuscules, sans accents,
   espaces -> tirets, seulement [a-z0-9-]. */
function normaliser(s) {
  return s.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase().trim()
          .replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, "").replace(/-+/g, "-");
}

const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

/* PBKDF2-SHA256 -> clé AES-256-GCM -> déchiffrement. Une phrase fausse fait
   échouer la vérification du tag GCM : aucune information ne fuit. */
async function ouvrirCoffre(phrase) {
  const base = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(normaliser(phrase)), "PBKDF2", false, ["deriveKey"]);
  const cle = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64(COFFRE.sel), iterations: COFFRE.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const clair = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64(COFFRE.iv) }, cle, b64(COFFRE.ct));
  return new TextDecoder().decode(clair);
}

document.addEventListener("DOMContentLoaded", () => {
  const $ = id => document.getElementById(id);
  $("diff").textContent = DIFFICULTE;
  $("iter").textContent = COFFRE.iter.toLocaleString("fr-FR");
  if (!window.crypto || !crypto.subtle) {
    $("etat").textContent = "Ce navigateur n'expose pas Web Crypto ici (il faut https:// ou un fichier local).";
    return;
  }
  let occupe = false;
  $("f").addEventListener("submit", async e => {
    e.preventDefault();
    if (occupe) return;
    occupe = true;
    $("ouvrir").disabled = true;
    $("etat").className = "";
    $("etat").textContent = "Les engrenages tournent…";
    try {
      const secret = await ouvrirCoffre($("phrase").value);
      $("secret").textContent = secret;
      $("secret").hidden = false;
      document.body.classList.add("ouvert");
      $("etat").className = "ok";
      $("etat").textContent = "Le coffre s'ouvre.";
    } catch {
      $("etat").className = "ko";
      $("etat").textContent = "Le coffre reste scellé.";
    } finally {
      occupe = false;
      $("ouvrir").disabled = false;
    }
  });
});
</script>
<style>
/* __LEURRE_CSS__ */
:root {
  --fond: #0d0b14; --carte: #17131f; --bord: #2c2538; --texte: #e8e2f0;
  --doux: #9a90aa; --or: #d9b45a; --ok: #6fd3a0; --ko: #e07a7a;
}
:root[data-theme="light"] {
  --fond: #f4f1ea; --carte: #fffdf8; --bord: #ddd4c2; --texte: #221d2b;
  --doux: #6b6276; --or: #9a7316; --ok: #1d7f52; --ko: #b13a3a;
}
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px 16px;
  background: radial-gradient(ellipse at top, #1e1830 0%, var(--fond) 60%) var(--fond);
  color: var(--texte); font: 16px/1.6 Georgia, "Times New Roman", serif;
}
.coffre {
  width: 100%; max-width: 560px; background: var(--carte); border: 1px solid var(--bord);
  border-radius: 14px; padding: 32px 28px; box-shadow: 0 20px 60px rgba(0,0,0,.45);
}
.sur-titre { margin: 0; color: var(--doux); letter-spacing: .25em; text-transform: uppercase; font-size: 12px; }
h1 { margin: 4px 0 24px; font-size: 34px; letter-spacing: .12em; color: var(--or); }
h2 { font-size: 15px; margin: 0 0 8px; color: var(--doux); font-weight: normal; font-style: italic; }
#serment { margin: 0 0 28px; padding-left: 14px; border-left: 2px solid var(--bord); }
label { display: block; font-size: 13px; color: var(--doux); margin-bottom: 6px; }
.ligne { display: flex; gap: 8px; flex-wrap: wrap; }
input {
  flex: 1 1 220px; min-width: 0; padding: 11px 12px; border-radius: 8px; border: 1px solid var(--bord);
  background: var(--fond); color: var(--texte); font: 15px ui-monospace, Consolas, monospace;
}
input:focus { outline: 2px solid var(--or); outline-offset: 1px; }
button {
  padding: 11px 20px; border-radius: 8px; border: 0; cursor: pointer;
  background: var(--or); color: #1a1408; font: bold 15px Georgia, serif;
}
button:disabled { opacity: .5; cursor: wait; }
#etat { min-height: 1.6em; margin: 14px 0 0; color: var(--doux); }
#etat.ok { color: var(--ok); } #etat.ko { color: var(--ko); }
#secret {
  margin-top: 16px; padding: 16px; border-radius: 8px; border: 1px dashed var(--or);
  font-size: 18px; white-space: pre-wrap; word-break: break-word;
}
.ouvert h1 { text-shadow: 0 0 18px var(--or); }
footer { margin-top: 28px; font-size: 12px; color: var(--doux); border-top: 1px solid var(--bord); padding-top: 12px; }
</style>
</head>
<body>
__COMMENTAIRE__
<main class="coffre"__ATTR__>
  <p class="sur-titre">Coffre n° 0</p>
  <h1>__TITRE__</h1>
  <h2>Le serment du gardien</h2>
  <p id="serment">__SERMENT__</p>
  <form id="f" autocomplete="off">
    <label for="phrase">Phrase de passe</label>
    <div class="ligne">
      <input id="phrase" spellcheck="false" placeholder="…">
      <button id="ouvrir" type="submit">Ouvrir</button>
    </div>
  </form>
  <p id="etat" role="status" aria-live="polite"></p>
  <div id="secret" hidden></div>
  <footer>Difficulté : <span id="diff"></span> · PBKDF2-SHA256 × <span id="iter"></span> · AES-256-GCM</footer>
</main>
</body>
</html>
"""


def ecrire_html(difficulte, coffre, commentaire, serment, attr=""):
    leurre_meta = base64.b64encode(
        "Trop facile. Le serpent ne dort pas dans les balises meta.".encode()).decode()
    leurre_css = "fausse piste, cherche ailleurs".encode().hex()
    page = (GABARIT
            .replace("__TITRE__", TITRE)
            .replace("__LEURRE_META__", leurre_meta)
            .replace("__LEURRE_CSS__", leurre_css)
            .replace("__DIFFICULTE__", difficulte)
            .replace("__COFFRE__", json.dumps(coffre))
            .replace("__COMMENTAIRE__", commentaire)
            .replace("__ATTR__", attr)
            .replace("__SERMENT__", serment))
    (ICI / "index.html").write_text(page, encoding="utf-8", newline="\n")


# ═════════════════════════════════════════════════════════════════════════════
# Génération
# ═════════════════════════════════════════════════════════════════════════════

def generer(difficulte: str, secret: str) -> dict:
    INDICES.mkdir(exist_ok=True)
    for f in INDICES.glob("vitrail_*.png"):   # nettoie une partie précédente
        f.unlink()

    (INDICES / "carnet.txt").write_text(CARNET, encoding="utf-8", newline="\n")
    (INDICES / "note.txt").write_text(NOTE_LEURRE, encoding="utf-8", newline="\n")

    info = {"difficulte": difficulte}
    if difficulte == "extreme":
        phrase, coords, mots = choisir_phrase_extreme()
        couples = " - ".join(f"{romain(n)}.{romain(p)}" for n, p in coords)
        m3 = ("TU AS LU CE QUI NE SE VOIT PAS. OUVRE INDICES/CARNET.TXT. VOICI SIX "
              f"COUPLES LIGNE.MOT EN CHIFFRES ROMAINS : {couples}. TOUTES LES LIGNES "
              "COMPTENT, LA PREMIERE EST I. UN MOT EST UNE SUITE DE LETTRES : "
              "APOSTROPHES, TIRETS ET PONCTUATION SEPARENT LES MOTS. ECRIS LES SIX "
              "MOTS DANS CET ORDRE, EN MINUSCULES ET SANS ACCENTS, RELIES PAR DES "
              "TIRETS, PUIS AJOUTE UN TIRET ET LA SOMME DES SIX NUMEROS DE LIGNE EN "
              "CHIFFRES ARABES.")
        # Étape 2 : M2 -> Vigenère(OUROBOROS) -> base64 -> miroir -> bits de largeur nulle
        s2 = base64.b64encode(vigenere(M2_EXTREME, CLE_VIGENERE).encode()).decode()[::-1]
        serment = disperser(SERMENT, octets_vers_zw(s2.encode()))
        porteur, canaux = VITRAIL_EXTREME, "GB"
        charge = xor(m3.encode(), TITRE.encode())
        commentaire, attr = COMMENTAIRE_EXTREME, ""
        info.update(coords=coords, mots=mots, s2=s2, m2=M2_EXTREME)
    else:
        lignes = CARNET.splitlines()
        mots = [normaliser(RNG.choice([m for m in mots_de(RNG.choice(lignes)) if len(m) >= 4] or ["cendre"]))
                for _ in range(4)]
        phrase = "-".join(mots) + f"-{RNG.randrange(10, 100)}"
        m3 = f"LA PHRASE DE PASSE EST : {phrase}"
        s2 = base64.b64encode(cesar(M2_MOYEN, 3).encode()).decode()
        serment = SERMENT
        porteur, canaux = VITRAIL_MOYEN, "R"
        charge = m3.encode()
        commentaire, attr = COMMENTAIRE_MOYEN, f' data-murmure="{s2}"'
        info.update(s2=s2, m2=M2_MOYEN)

    # Étape 3 : les vitraux (un seul porteur, tous bruités pareil)
    for n in range(1, NB_VITRAUX + 1):
        img = fabriquer_vitrail()
        if n == porteur:
            img = cacher_lsb(img, charge, canaux)
        img.save(INDICES / f"vitrail_{n}.png", optimize=True)

    # Étape 4 : le coffre
    coffre = chiffrer_secret(secret, phrase)
    ecrire_html(difficulte, coffre, commentaire, serment, attr)
    info.update(phrase=phrase, m3=m3, porteur=porteur, canaux=canaux, coffre=coffre)
    return info


def verifier(info: dict, secret: str):
    """Résout le jeu en repartant UNIQUEMENT des fichiers écrits sur disque."""
    page = (ICI / "index.html").read_text(encoding="utf-8")
    if info["difficulte"] == "extreme":
        s2 = zw_vers_octets(page).decode()
        m2 = vigenere(base64.b64decode(s2[::-1]).decode(), CLE_VIGENERE, -1)
        assert m2 == M2_EXTREME, "étape 2 KO"
        m3 = xor(lire_lsb(Image.open(INDICES / f"vitrail_{VITRAIL_EXTREME}.png"), "GB"),
                 TITRE.encode()).decode()
        assert m3 == info["m3"], "étape 3 KO"
        rom = {"I": 1, "V": 5, "X": 10}
        def de_romain(s):
            v = [rom[c] for c in s]
            return sum(-a if a < b else a for a, b in zip(v, v[1:] + [0]))
        lignes = (INDICES / "carnet.txt").read_text(encoding="utf-8").splitlines()
        couples = re.findall(r"\b([IVX]+)\.([IVX]+)\b", m3)
        mots = [normaliser(mots_de(lignes[de_romain(l) - 1])[de_romain(m) - 1]) for l, m in couples]
        phrase = "-".join(mots) + f"-{sum(de_romain(l) for l, _ in couples)}"
    else:
        s2 = re.search(r'data-murmure="([^"]+)"', page).group(1)
        m2 = cesar(base64.b64decode(s2).decode(), -3)
        assert m2 == M2_MOYEN, "étape 2 KO"
        m3 = lire_lsb(Image.open(INDICES / f"vitrail_{VITRAIL_MOYEN}.png"), "R").decode()
        phrase = m3.split(": ", 1)[1]
    assert phrase == info["phrase"], "étape 4 KO"
    coffre = json.loads(re.search(r"const COFFRE = (\{.*?\});", page).group(1))
    assert dechiffrer_secret(coffre, phrase) == secret, "déchiffrement KO"
    try:
        dechiffrer_secret(coffre, phrase + "x")
        raise AssertionError("une mauvaise phrase a ouvert le coffre !")
    except Exception as e:
        if isinstance(e, AssertionError):
            raise


# ═════════════════════════════════════════════════════════════════════════════
# SOLUTION.md
# ═════════════════════════════════════════════════════════════════════════════

def ecrire_solution(info: dict):
    c = info["coffre"]
    if info["difficulte"] == "extreme":
        tableau = "\n".join(
            f"| {romain(n)}.{romain(p)} | {n} | {p} | `{m}` |"
            for (n, p), m in zip(info["coords"], info["mots"]))
        corps = f"""## Étape 1 — Le commentaire HTML (source de la page)

Juste après `<body>`, un poème. **Acrostiche** (« lis-les debout » = à la
verticale) : **O**ublie, **U**n, **R**egarde, **O**ù, **B**rise, **O**uvre,
**R**ends, **Ô**, **S**ans → **`{CLE_VIGENERE}`** = la clé de Vigenère.

Les vers donnent aussi la recette :
- « regarde entre elles [les lettres du serment], là où rien ne prend de place »
  → des caractères de **largeur nulle** sont glissés dans le paragraphe `#serment` ;
- « le zéro est un espace » → `U+200B ZERO WIDTH SPACE` = bit 0 ;
  « le un refuse de joindre » → `U+200C ZERO WIDTH NON-JOINER` = bit 1 ;
- « brise d'abord le miroir » → inverser la chaîne obtenue ;
- « les soixante-quatre portes » → décoder en base64 ;
- « rends au serpent ce que sa clé lui a pris » → déchiffrer Vigenère, clé `{CLE_VIGENERE}`
  (lettres A-Z seulement, le reste ne fait pas avancer la clé).

Leurres : `<meta name="cle">` (base64 → « Trop facile… ») et le commentaire CSS
(hex → « fausse piste, cherche ailleurs »). `indices/note.txt` est aussi un leurre.

## Étape 2 — Le serment invisible

Bits (MSB d'abord) → {len(info['s2'])} caractères ASCII. Chaîne obtenue :

```
{info['s2']}
```

Inversée, décodée base64, puis Vigenère inverse avec `{CLE_VIGENERE}` :

> {info['m2']}

→ clé de 9 lettres → **`indices/vitrail_{info['porteur']}.png`**, LSB du **vert puis
du bleu**, longueur sur 4 octets big-endian, puis XOR avec **`{TITRE}`** (le `<title>`).

## Étape 3 — La stéganographie

Message extrait de `vitrail_{info['porteur']}.png` :

> {info['m3']}

## Étape 4 — Le carnet

| Couple | Ligne | Mot n° | Mot normalisé |
|---|---|---|---|
{tableau}

Somme des lignes = **{sum(n for n, _ in info['coords'])}**.

## Phrase de passe

```
{info['phrase']}
```

## Script de résolution (étapes 2 et 3)

```python
import base64
from PIL import Image

page = open("index.html", encoding="utf-8").read()
bits = "".join("0" if ch == "\\u200b" else "1" for ch in page if ch in "\\u200b\\u200c")
s2 = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode()
m = base64.b64decode(s2[::-1]).decode()
K, out, j = "{CLE_VIGENERE}", [], 0
for ch in m:
    if "A" <= ch <= "Z":
        out.append(chr((ord(ch) - ord(K[j % len(K)])) % 26 + 65)); j += 1
    else:
        out.append(ch)
print("".join(out))

img = Image.open("indices/vitrail_{info['porteur']}.png").convert("RGB")
bits = "".join(str(c & 1) for px in img.getdata() for c in (px[1], px[2]))
data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) // 8 * 8, 8))
n = int.from_bytes(data[:4], "big"); k = b"{TITRE}"
print(bytes(b ^ k[i % len(k)] for i, b in enumerate(data[4:4+n])).decode())
```
"""
    else:
        corps = f"""## Étape 1 — Commentaire HTML
Il pointe vers l'attribut `data-murmure` de `<main>` : base64 puis César −3.

## Étape 2 — Le murmure
`{info['s2']}` → base64 → César −3 :

> {info['m2']}

## Étape 3 — Stéganographie
`indices/vitrail_{info['porteur']}.png`, LSB du rouge :

> {info['m3']}

## Phrase de passe
```
{info['phrase']}
```
"""
    texte = f"""# SOLUTION — COFFRE-ZERO ({info['difficulte']})

> ⚠️ **NE PAS DÉPLOYER CE FICHIER.** Il donne la phrase de passe.
> Il est régénéré à chaque `python encode.py`.

Paramètres du coffre : PBKDF2-SHA256 × {c['iter']:,} · sel `{c['sel']}` · IV `{c['iv']}` · AES-256-GCM.

{corps}
La saisie est normalisée (minuscules, sans accents, espaces → tirets) : les
majuscules ou les accents ne gênent pas.
"""
    (ICI / "SOLUTION.md").write_text(texte, encoding="utf-8", newline="\n")


# ═════════════════════════════════════════════════════════════════════════════

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--secret", help="la phrase à cacher (sinon : tirée au hasard)")
    ap.add_argument("--difficulte", choices=["moyen", "extreme"], default=DIFFICULTE)
    a = ap.parse_args()

    secret = a.secret or secret_aleatoire()
    print(f"Génération ({a.difficulte})… PBKDF2 × {ITERATIONS:,}")
    info = generer(a.difficulte, secret)
    ecrire_solution(info)
    verifier(info, secret)
    print("Vérification automatique : la chaîne complète se résout depuis les fichiers. OK")
    print()
    print("SECRET (affiché une seule fois, écrit nulle part en clair) :")
    print(f"    {secret}")


if __name__ == "__main__":
    main()
