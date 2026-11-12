# COFFRE-ZERO — chasse au trésor cryptographique

Une page web autonome qui contient un secret chiffré en **AES-256-GCM**
(clé dérivée par **PBKDF2-SHA256 × 600 000**, sel et IV aléatoires, via la Web
Crypto API du navigateur, sans aucune librairie). Pour l'ouvrir, il faut
remonter une énigme en plusieurs étapes.

## Contenu du dossier

| Fichier | Rôle | À déployer ? |
|---|---|---|
| `index.html` | le coffre + l'énigme | ✅ oui |
| `indices/` | vitraux (dont un porte un message caché), carnet, leurre | ✅ oui |
| `encode.py` | génère tout (stégo, ciphertext, page, soluce) | ❌ non (il donne la méthode) |
| `SOLUTION.md` | la soluce complète + la phrase de passe | ❌ **jamais** |
| `README.md` | ce fichier | ❌ non |

## Héberger

Il suffit de publier **`index.html` et le dossier `indices/`** tels quels sur
n'importe quel hébergeur statique : GitHub Pages, Netlify (glisser-déposer),
Cloudflare Pages, Vercel, un serveur Apache/Nginx…

```
site/
├── index.html
└── indices/
    ├── carnet.txt
    ├── note.txt
    └── vitrail_1.png … vitrail_12.png
```

- La page fonctionne **hors-ligne** : aucune requête réseau au runtime.
- Web Crypto exige un « contexte sécurisé » : **https://**, `localhost`, ou
  le fichier ouvert en local (double-clic). Un `http://` nu sur un vrai
  domaine ne marchera pas.
- Les joueurs doivent pouvoir ouvrir `indices/...` par leur URL (le jeu leur
  dit quel fichier aller chercher). Inutile d'activer le listing de dossier.

## Lancer une partie

```bash
pip install pillow cryptography
python encode.py                          # secret tiré au hasard, affiché une fois
python encode.py --secret "Ma phrase"     # votre propre secret
python encode.py --difficulte moyen       # version ~30 min
```

Chaque exécution régénère **tout** : nouveau sel, nouvel IV, nouvelle phrase
de passe, nouveaux vitraux, nouvelle `SOLUTION.md`. Le script vérifie ensuite
automatiquement que l'énigme se résout bien de bout en bout à partir des
fichiers écrits.

La difficulté par défaut est la constante `DIFFICULTE` en haut de
`encode.py` (elle est recopiée en haut de `index.html`).

## Pour le joueur

« Il y a un coffre. Il y a un serment. Tout ce qu'il faut est dans la page
et dans le dossier `indices/`. Bonne chance. »

Outils utiles : afficher le code source (Ctrl+U), un peu de Python ou
CyberChef, et de la patience.
