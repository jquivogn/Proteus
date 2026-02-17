# SMC — Les concepts mathématiques expliqués simplement

## 1. L'arithmétique modulaire

C'est le socle de presque toute la cryptographie. L'idée est simple :
on fait des calculs dans un espace fini, comme une horloge qui revient
à 0 après 12.

Dans le SMC, on travaille toujours sur des octets, donc des entiers
entre 0 et 255. Quand un calcul dépasse 255, on "revient au début" :

```
200 + 100 = 300  →  300 mod 256 = 44
```

C'est noté (a + b) mod 256, ou &0xFF en code.

**Pourquoi c'est utile ?** Parce que l'opération inverse existe toujours.
Si on a ajouté k, on peut retrouver l'original en soustrayant k.
L'information n'est jamais détruite, juste transformée — propriété
indispensable pour pouvoir déchiffrer.

---

## 2. Le XOR (ou exclusif, ⊕)

Le XOR est l'opération la plus utilisée en cryptographie. Sur un bit :

```
0 ⊕ 0 = 0
0 ⊕ 1 = 1
1 ⊕ 0 = 1
1 ⊕ 1 = 0   ← deux fois le même = retour à 0
```

Sa propriété magique : **appliquer deux fois annule l'opération**.

```
message ⊕ clé = chiffré
chiffré ⊕ clé = message   ← on retrouve l'original
```

C'est la base du chiffrement par flot (one-time pad). Seul, le XOR
n'est pas sûr si la clé se répète. C'est pourquoi le SMC le combine
avec d'autres opérations.

---

## 3. Les rotations de bits (ROL / ROR)

Un octet est une suite de 8 bits, par exemple :

```
10110100
```

Une rotation gauche de 2 positions décale tous les bits vers la gauche,
et les bits qui "tombent" à gauche reviennent à droite :

```
ROL(10110100, 2) = 11010010
```

Contrairement à un simple décalage, aucun bit n'est perdu — ils font
le tour. L'opération inverse (ROR, rotation droite) restaure exactement
l'original. C'est donc **bijectif** : chaque entrée possible donne une
sortie différente.

---

## 4. La bijectivité — pourquoi c'est fondamental

Une fonction f est bijective si elle met en correspondance chaque entrée
avec **exactement une** sortie, et chaque sortie correspond à **exactement
une** entrée. Autrement dit : elle est inversible sans perte.

```
Bijective :     {0,1,2,3} → {3,1,0,2}   ✓ (chaque valeur apparaît une fois)
Non bijective : {0,1,2,3} → {0,0,1,2}   ✗ (0 apparaît deux fois → perte)
```

**Dans le SMC**, les primitives ADD, SUB, XOR, ROL, ROR, MUL (avec k
impair) sont toutes bijectives mod 256. Cela garantit qu'aucune
information n'est détruite pendant le chiffrement, et que le
déchiffrement est toujours possible.

La multiplication mérite une note : (b × k) mod 256 n'est bijective
que si k est impair. C'est pourquoi le code force k à être impair avec
`k | 1`. La raison mathématique : un nombre impair est toujours
premier avec 256 (= 2⁸), et deux nombres premiers entre eux ont
toujours un inverse multiplicatif modulo l'un d'eux.

---

## 5. Le réseau de Feistel

C'est la structure qui permet au SMC d'utiliser des fonctions **non
nécessairement inversibles** tout en garantissant que le chiffrement
reste réversible. C'est la même idée qui est à la base du DES (1977).

### Principe

On coupe le bloc de 8 octets en deux moitiés L (gauche) et R (droite).
À chaque ronde :

```
L_nouveau  =  R
R_nouveau  =  L  ⊕  F(R)
```

où F est n'importe quelle fonction — même destructrice. Le XOR final
rend tout réversible car :

```
R  =  L_nouveau
L  =  R_nouveau  ⊕  F(L_nouveau)
```

Il suffit de rejouer F sur L_nouveau (qu'on connaît) pour retrouver L
par XOR. F n'a jamais besoin d'être inversée directement.

### Visualisation sur 2 rondes

```
Ronde 1 :       Ronde 2 :
L₀  R₀          L₁  R₁
│   │            │   │
│   ├──► F ──►  │   ├──► F ──►
│   │       │   │   │       │
└─⊕─┘       │   └─⊕─┘       │
    │        │       │        │
   L₁  R₁  ─┘      L₂  R₂  ─┘
```

Plus on ajoute de rondes, plus le mélange est profond et plus l'effet
d'avalanche (voir section 8) est fort.

---

## 6. Le PRNG et la notion de graine (seed)

Un PRNG (Pseudo-Random Number Generator) est un algorithme qui produit
une séquence de nombres qui *ressemble* à de l'aléatoire, mais qui est
en réalité entièrement déterminée par sa valeur initiale : la **graine**.

```
graine 42  →  7, 193, 4, 88, 201, 12, ...  (toujours la même séquence)
graine 43  →  251, 6, 177, 39, 14, 200, ...  (séquence complètement différente)
```

**Dans le SMC**, le PRNG utilisé est XorShift128+, dont l'état interne
est représenté par deux entiers de 64 bits. À chaque appel, l'état
évolue via des opérations XOR et des décalages de bits :

```
s1  ^=  s0
s0  =  ROL(s0, 55)  ^  s1  ^  (s1 << 14)
s1  =  ROL(s1, 36)
résultat = (s0 + s1) mod 2⁶⁴
```

Sa période est 2¹²⁸ − 1 : on peut générer 2¹²⁸ nombres avant que la
séquence ne se répète — un nombre astronomiquement grand.

**La synchronisation** repose entièrement sur cette propriété : si
l'émetteur et le récepteur initialisent leur PRNG avec la même graine,
ils génèrent exactement la même séquence et donc les mêmes choix
de primitives dans le même ordre.

---

## 7. La dérivation de clé (PBKDF2)

On ne se sert jamais directement de la clé brute. On la fait passer
par PBKDF2 (Password-Based Key Derivation Function 2), qui produit
une clé dérivée de longueur quelconque.

```
master_key = PBKDF2-SHA256(key, seed, iterations=2000, length=64)
```

Trois propriétés importantes :

**Étirement** : Les 2000 itérations rendent une attaque par force brute
2000 fois plus coûteuse qu'une attaque directe sur SHA-256.

**Avalanche** : Un seul bit changé dans `key` ou `seed` produit une
`master_key` complètement différente (propriété de SHA-256).

**Séparation des domaines** : La même clé avec deux seeds différentes
produit deux master_keys sans aucune relation mathématique entre elles —
ce qui isole les sessions les unes des autres.

---

## 8. L'effet d'avalanche

C'est le critère principal de qualité d'un chiffrement : modifier
**un seul bit** dans le message d'entrée doit modifier environ
**50% des bits** en sortie, de manière imprévisible.

Le SMC mesure cet effet via la **distance de Hamming** entre deux
ciphertexts obtenus depuis des plaintexts différant d'un seul bit :

```
distance_Hamming(a, b) = nombre de bits différents entre a et b
```

Le test T2 a mesuré **48.0% ± 3.1%** — très proche de l'idéal
théorique de 50%. C'est la signature d'un bon mélange cryptographique.
Un résultat inférieur à 40% indiquerait une structure exploitable.

---

## 9. L'entropie de Shannon

L'entropie mesure la **quantité d'information** (ou d'imprévisibilité)
d'une source. Pour une séquence d'octets, elle est définie par :

```
H = − Σ  p(x) × log₂(p(x))
```

où p(x) est la fréquence de l'octet x dans les données.

- H = 0 bits/octet : données complètement prévisibles (ex. : b"\x00" × N)
- H = 8 bits/octet : distribution parfaitement uniforme sur 0..255

Un bon ciphertext doit avoir H ≥ 7.0 bits/octet. Le SMC atteint
H ≈ 7.3 bits/octet sur des textes variés.

**Note sur le biais de Miller-Madow** : sur moins de ~512 octets,
l'estimateur de Shannon sous-estime l'entropie réelle. C'est un biais
statistique bien documenté, non un défaut du chiffrement.

---

## 10. Le checksum HMAC (intégrité)

Le SMC calcule un code d'intégrité sur l'ensemble du ciphertext :

```
checksum = SHA-256(master_key ∥ header ∥ IV ∥ round_meta ∥ données)[:4]
```

Si un seul octet du ciphertext est modifié pendant le transit, le
checksum recalculé ne correspondra plus — le déchiffrement sera rejeté.
Cela protège contre la falsification (attaque dite "bit flipping").

La master_key est incluse dans le calcul, ce qui signifie qu'un
attaquant sans la clé ne peut pas forger un checksum valide — même
s'il connaît la structure exacte du format. C'est la propriété
fondamentale d'un **MAC (Message Authentication Code)**.

---

## Résumé des dépendances entre concepts

```
Arithmétique modulaire
    └──► Bijectivité des primitives (ADD, MUL, ROL...)
             └──► Sécurité de la fonction F

XOR
    └──► Réversibilité du réseau de Feistel
             └──► Déchiffrement garanti même avec F non bijective

Graine + PBKDF2
    └──► master_key dérivée
             ├──► PRNG synchronisé → sélection stochastique des primitives
             └──► Clés de ronde → paramètre k de chaque primitive

IV aléatoire
    └──► PRNG distinct par chiffrement → métamorphisme (T6)

Effet d'avalanche + Entropie + HMAC
    └──► Métriques de validation du prototype (T2, T3, T7)
```
