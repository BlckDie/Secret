# SOLUTION — COFFRE-ZERO (extreme)

> ⚠️ **NE PAS DÉPLOYER CE FICHIER.** Il donne la phrase de passe.
> Il est régénéré à chaque `python encode.py`.

Paramètres du coffre : PBKDF2-SHA256 × 600,000 · sel `tsH6MDJDGwHerW3oNeNvew==` · IV `caMXspnGjlS1ATr+` · AES-256-GCM.

## Étape 1 — Le commentaire HTML (source de la page)

Juste après `<body>`, un poème. **Acrostiche** (« lis-les debout » = à la
verticale) : **O**ublie, **U**n, **R**egarde, **O**ù, **B**rise, **O**uvre,
**R**ends, **Ô**, **S**ans → **`OUROBOROS`** = la clé de Vigenère.

Les vers donnent aussi la recette :
- « regarde entre elles [les lettres du serment], là où rien ne prend de place »
  → des caractères de **largeur nulle** sont glissés dans le paragraphe `#serment` ;
- « le zéro est un espace » → `U+200B ZERO WIDTH SPACE` = bit 0 ;
  « le un refuse de joindre » → `U+200C ZERO WIDTH NON-JOINER` = bit 1 ;
- « brise d'abord le miroir » → inverser la chaîne obtenue ;
- « les soixante-quatre portes » → décoder en base64 ;
- « rends au serpent ce que sa clé lui a pris » → déchiffrer Vigenère, clé `OUROBOROS`
  (lettres A-Z seulement, le reste ne fait pas avancer la clé).

Leurres : `<meta name="cle">` (base64 → « Trop facile… ») et le commentaire CSS
(hex → « fausse piste, cherche ailleurs »). `indices/note.txt` est aussi un leurre.

## Étape 2 — Le serment invisible

Bits (MSB d'abord) → 616 caractères ASCII. Chaîne obtenue :

```
uMVSD90SHZVUGJEIW9URgwkQShkVPBiVONFSTlEIsMFSPdEIZhETTRFITVEITlkTXxEITNEIRZkSSBiWXtUSDFVWTBCTJBiQNBiRSREIGlESN9URggkSTBSVXxUTgcVTFBySTVVUGBSWJl0TZFFIuYUVS10RXFEIMJFITlkVPVlRDNEIP1EIIVUWCZ0QVBCLH90Ua5USHBFIKN0UVBCLK50UMFlRgc0UTp1RTpERgYlRV9ETLByRXpFIuk0UKFkVMREIGNFILZEUUBiSPpFSgM1QgwCSKlUWgw0TIByRLd1QgckVGByUEBFRTR1RSBiLN9EVgIkVggkVPlFIZJFIMNFIWhkSDlEWg8EIXZFVJJUVgYFWgwiWXxkWEBiRJhUVWVFITVFIJZkWTByTSBySXxERgUlRWBFIJZFITNEUK90Vg0kUBN0RgMVRggkWWByUEByRapFIuYkWUBSVHByVSBiSTNFSLllWgclUgYlRDFkRIByUEByUD9ESTBiRMNVRJVEIT1EIIVUSSBCRXJlRVdVTgklWgskQSJFIsQ1UUNkUGdFIJNlSHpUSSByVaBiSCJkUgsETDZFIIV0URZkVNByUEBiLTx0QLBiQWNEU
```

Inversée, décodée base64, puis Vigenère inverse avec `OUROBOROS` :

> BIEN JOUE. LE SERPENT DORT DANS LE DOSSIER INDICES, DANS LE VITRAIL DONT LE NUMERO EGALE LE NOMBRE DE LETTRES DE SA CLE. LIS LE BIT DE POIDS FAIBLE DU VERT PUIS DU BLEU DE CHAQUE PIXEL, DE GAUCHE A DROITE ET DE HAUT EN BAS. ASSEMBLE LES BITS PAR HUIT, LE PLUS FORT EN PREMIER. LES QUATRE PREMIERS OCTETS, GROS BOUTIENS, DONNENT LA LONGUEUR DU MESSAGE. CHAQUE OCTET QUI SUIT EST MASQUE PAR UN OU EXCLUSIF AVEC LE TITRE DE CETTE PAGE, REPETE AUTANT QUE NECESSAIRE.

→ clé de 9 lettres → **`indices/vitrail_9.png`**, LSB du **vert puis
du bleu**, longueur sur 4 octets big-endian, puis XOR avec **`COFFRE-ZERO`** (le `<title>`).

## Étape 3 — La stéganographie

Message extrait de `vitrail_9.png` :

> TU AS LU CE QUI NE SE VOIT PAS. OUVRE INDICES/CARNET.TXT. VOICI SIX COUPLES LIGNE.MOT EN CHIFFRES ROMAINS : XXIV.V - XIII.VII - VI.IV - XX.VII - XXVIII.XI - IV.IV. TOUTES LES LIGNES COMPTENT, LA PREMIERE EST I. UN MOT EST UNE SUITE DE LETTRES : APOSTROPHES, TIRETS ET PONCTUATION SEPARENT LES MOTS. ECRIS LES SIX MOTS DANS CET ORDRE, EN MINUSCULES ET SANS ACCENTS, RELIES PAR DES TIRETS, PUIS AJOUTE UN TIRET ET LA SOMME DES SIX NUMEROS DE LIGNE EN CHIFFRES ARABES.

## Étape 4 — Le carnet

| Couple | Ligne | Mot n° | Mot normalisé |
|---|---|---|---|
| XXIV.V | 24 | 5 | `horloge` |
| XIII.VII | 13 | 7 | `engouffre` |
| VI.IV | 6 | 4 | `corneille` |
| XX.VII | 20 | 7 | `allumee` |
| XXVIII.XI | 28 | 11 | `coffre` |
| IV.IV | 4 | 4 | `cuivre` |

Somme des lignes = **95**.

## Phrase de passe

```
horloge-engouffre-corneille-allumee-coffre-cuivre-95
```

## Script de résolution (étapes 2 et 3)

```python
import base64
from PIL import Image

page = open("index.html", encoding="utf-8").read()
bits = "".join("0" if ch == "\u200b" else "1" for ch in page if ch in "\u200b\u200c")
s2 = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode()
m = base64.b64decode(s2[::-1]).decode()
K, out, j = "OUROBOROS", [], 0
for ch in m:
    if "A" <= ch <= "Z":
        out.append(chr((ord(ch) - ord(K[j % len(K)])) % 26 + 65)); j += 1
    else:
        out.append(ch)
print("".join(out))

img = Image.open("indices/vitrail_9.png").convert("RGB")
bits = "".join(str(c & 1) for px in img.getdata() for c in (px[1], px[2]))
data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) // 8 * 8, 8))
n = int.from_bytes(data[:4], "big"); k = b"COFFRE-ZERO"
print(bytes(b ^ k[i % len(k)] for i, b in enumerate(data[4:4+n])).decode())
```

La saisie est normalisée (minuscules, sans accents, espaces → tirets) : les
majuscules ou les accents ne gênent pas.
