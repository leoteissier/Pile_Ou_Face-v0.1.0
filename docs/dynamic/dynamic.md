# Mode Dynamique — Guide utilisateur

Le mode dynamique permet d’exécuter un binaire avec un payload personnalisé et d’observer précisément ce qui se passe en mémoire pendant l’exécution.

L’objectif est de fournir une compréhension concrète du fonctionnement de la pile, des corruptions mémoire et du flux d’exécution.

---

## Vue d’ensemble

L’interface est organisée en plusieurs étapes :

1. Choix du binaire  
2. Entrée du payload  
3. Aperçu du payload  
4. Exécution (Run Trace)  
5. Analyse dynamique (pile, registres, assembleur)  
6. Diagnostics  

Chaque étape correspond à une zone de l’interface.

---

## 1. Choix du binaire

Le fichier ELF est chargé automatiquement.

Tu peux :
- utiliser le binaire par défaut
- charger un autre binaire

Optionnel :
- ajouter le fichier source `.c`

Ajouter le `.c` permet :
- d’obtenir les vrais noms de variables
- d’améliorer la reconstruction de la pile
- d’avoir une analyse plus précise

[Screenshot 1 — sélection du binaire]

---

## 2. Payload d’entrée

Plusieurs formats sont acceptés.

### Expressions Python (recommandé)

Exemples :
A*80
cyclic(128)
b"A"*64


### Fichier

- importer un fichier (.txt, .bin, etc.)
- le contenu est utilisé comme payload

### Script pwntools

- support partiel des scripts pwntools
- extraction automatique du payload depuis :
  - send
  - sendline
  - sendafter

### Exploit Helper

- aide à générer des payloads
- utile pour les offsets, padding, structures

[Screenshot 2 — payload builder]

---

## 3. Aperçu du payload

Avant exécution, le payload est affiché :

- version ASCII
- version HEX
- taille exacte (en bytes)

Fonctionnalités :
- historique des payloads
- possibilité de réutiliser un payload précédent
- clear/reset

Cela permet de vérifier que le payload correspond exactement à ce qui sera envoyé.

[Screenshot 3 — preview et historique]

---

## 4. Exécution (Run Trace)

Le bouton "Run Trace" :

- charge le binaire dans le moteur d’exécution
- injecte le payload (argv ou stdin)
- exécute le programme via Unicorn
- enregistre une trace complète

Important :
- le binaire n’est jamais modifié
- seul le payload change

Chaque exécution produit une nouvelle trace.

[Screenshot 4 — bouton Run Trace]

---

## 5. Analyse dynamique

Après l’exécution, plusieurs vues sont disponibles.

### 5.1 Vue pile (Stack)

La pile est reconstruite en objets lisibles :

- variables locales
- buffers
- arguments
- saved rbp
- return address

Ce n’est pas un dump brut, mais une reconstruction basée sur :
- analyse statique
- observations runtime
- éventuellement le code C

Objectif : rendre la pile compréhensible.

[Screenshot 5 — stack]

---

### 5.2 Registres

Les registres principaux sont affichés :

- RIP (instruction en cours)
- RSP (pointeur de pile)
- RBP (base de pile)

Les valeurs correspondent à l’état au moment critique.

[Screenshot 6 — registres]

---

### 5.3 Vue assembleur

Affichage des instructions exécutées :

- trace instruction par instruction
- instruction courante surlignée
- instructions critiques mises en avant (strcpy, ret, etc.)

Permet de comprendre l’impact du payload sur le programme.

[Screenshot 7 — asm]

---

## 6. Diagnostics

Le système analyse automatiquement le résultat.

### Crash (fatal)

- saut vers une adresse invalide
- segmentation fault

### Corruption

- overflow détecté
- modification de la pile
- saved rbp écrasé

### Détournement contrôlé

- return address écrasée
- exécution redirigée vers une fonction valide (ex: win)

Important :
Un détournement réussi n’est pas un échec, mais une exploitation.

[Screenshot 8 — diagnostics]

---

## Exemple

### Code vulnérable
char buffer[32];
strcpy(buffer, argv[1]);


### Payload
A*80


### Résultat

- dépassement du buffer
- corruption de la pile
- écrasement de la return address
- crash ou contrôle du flux

---

## Concepts importants

- Le binaire reste constant
- Le payload change à chaque exécution
- Chaque run produit une nouvelle trace
- La pile est reconstruite pour être lisible

---

## Cas supportés

- overflow via argv
- overflow via stdin
- détection d’offset avec cyclic
- ret2win
- visualisation de corruption mémoire

---

## Limitations

- parsing pwntools partiel
- certaines reconstructions de pile approximatives
- support principal x86_64

---

## Résumé

Le mode dynamique transforme :

"je lance un payload"

en :

"je vois exactement ce qui se passe en mémoire"

Ce mode permet de comprendre réellement les mécanismes d’exploitation.
