# Détails d’émulation Unicorn (pour les outils internes)

## Objectif
Ce document explique, de manière détaillée et pragmatique, ce que l’outillage émule réellement via Unicorn, comment l’émulation est pilotée par nos scripts, et quelles parties du « processeur » et de l’environnement d’exécution sont (ou ne sont pas) prises en charge.

Il est conçu pour des développeurs internes qui veulent comprendre la fidélité de la trace, ses limites, et comment l’extension VS Code consomme les données.

## Résumé rapide

- Unicorn émule le CPU x86/x86_64 **au niveau instruction**, sans OS réel.
- Nous émulerons **le CPU**, **la mémoire**, un **stack minimal**, et **une syscall (read)** pour injecter stdin.
- Nous **n’émulons pas** un noyau complet, pas de scheduler, pas de mémoire virtuelle réelle, pas d’ELF loader complet, pas de libc.
- Le loader ELF est **minimal** : segments PT_LOAD mappés, PT_INTERP optionnel.

## Que fait Unicorn exactement ?

Unicorn est un moteur d’émulation CPU basé sur QEMU. Il fournit :

- Un cœur CPU (x86/x86_64 ici) qui exécute des instructions en mémoire.
- Une mémoire « plate » que l’on mappe manuellement (RAM fictive).
- Des hooks (callbacks) sur exécution d’instructions, interruptions et syscalls.

Ce qu’Unicorn **ne fournit pas** nativement :

- Un OS, des syscalls ou un environnement utilisateur complet.
- La gestion des fichiers, du réseau, ou des threads.
- Un loader ELF complet (c’est à nous de mapper les segments).

## Notre modèle d’émulation

### 1) Détection ELF vs raw

Notre pipeline distingue :

- **Raw** : un blob de bytes x86 mappé à une base fixe (`config.base`).
- **ELF** : un exécutable ELF minimalement chargé (segments PT_LOAD).

Le choix se fait via la signature ELF (`\x7fELF`).

### 2) CPU et registres

- Architecture : x86 32-bit ou x86_64 64-bit
- Unicorn exécute **les instructions CPU** (décodage, micro-ops, etc.)
- Nous lisons les registres après chaque instruction via hooks
- Registres collectés :
  - 64-bit : rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip, r8–r15
  - 32-bit : eax, ebx, ecx, edx, esi, edi, ebp, esp, eip

Les registres sont sérialisés en hex dans le JSON.

### 3) Mémoire

Nous créons une mémoire virtuelle simple :

- **Code** : mappé à `config.base`
- **Stack** : mappé à `config.stack_base` sur `config.stack_size`
- **ELF** : segments PT_LOAD mappés à leurs VADDR (avec base si PIE)
- **PT_INTERP** : mappé si demandé (interpréteur dynamique)

Il n’y a **pas** de pagination réelle ni de permissions fines : on mappe en RWX.

### 4) Stack et initialisation

Deux chemins :

- **Raw** : on mappe la stack et positionne SP/BP en haut de pile.
- **ELF** : on construit une stack minimale compatible Linux :
  - argc, argv, envp, auxv
  - argv[0] = chemin du binaire
  - argv[1] optionnel via `--argv1`

Cette stack permet d’exécuter des binaires simples qui s’attendent à une structure Linux de base.

### 5) Syscalls (stdin uniquement)

Unicorn ne fournit pas d’OS. Nous interceptons uniquement `read(0, ...)` :

- 32-bit : via `int 0x80`, sys_read = 3
- 64-bit : via `syscall`, sys_read = 0

Si le code appelle `read(0, buf, size)`, nous copions les bytes de `config.stdin_data` dans la mémoire du guest et retournons la taille lue.

Aucun autre syscall n’est géré : open, write, exit, mmap, etc. ne sont **pas** émulés.

### 6) Instruction hooks et snapshots

À chaque instruction, nous :

- Lisons les bytes de l’instruction (désassemblage via Capstone si dispo)
- Lisons les registres
- Capturons un « window » de stack (`config.stack_entries`)

Le snapshot produit :

```
{
  "step": 1,
  "rip": "0x...",
  "rsp": "0x...",
  "instr": "mov ...",
  "stack": [...],
  "registers": [...]
}
```

Ces snapshots sont consommés par le webview pour rendre la pile et les registres.

## Emulation ELF en détail

### Mapping des segments

- On parse le header ELF et les Program Headers.
- Pour chaque segment PT_LOAD :
  - Mappe la zone mémoire (alignée page)
  - Écrit les bytes du fichier sur la zone mappée

### PIE et base d’adresse

- Si l’ELF est PIE (ET_DYN), on mappe à `config.base`.
- Sinon base = 0 et on garde les adresses ELF natives.

### PT_INTERP

Si l’ELF contient un PT_INTERP :

- On tente de charger l’interpréteur
- On le mappe à `config.interp_base`
- On peut démarrer l’exécution directement dans l’interpréteur (`--start-interp`)

### Start symbol

Si `--start-symbol` est fourni :

- On résout l’adresse via `nm`
- On démarre l’émulation à ce symbole

### Enrichissement addr2line

Si `addr2line` est disponible et que des snapshots existent :

- On transforme les adresses RIP -> file:line
- On enrichit chaque snapshot avec `file`, `line`, `func`

## Ce qui est émulé vs non émulé

### Emulé

- CPU x86/x86_64 (instructions)
- Mémoire mappée (code + stack)
- Stack minimale (argc/argv/auxv)
- read(0, ...) via injection stdin
- Désassemblage (si Capstone disponible)

### Non émulé

- OS / kernel réel
- syscalls autres que read
- signaux / exceptions OS
- threads / scheduling
- fichiers, réseau, sockets
- protections mémoire fines (NX/RO/RW)
- loader ELF complet (relocations avancées, dynlink)

## Conséquences pratiques

- Les programmes simples (sans syscalls complexes) fonctionnent bien.
- Les binaires qui dépendent de libc/dynlink peuvent échouer ou être incomplets.
- `max_steps` limite la trace pour éviter un affichage trop lourd.
- Le désassemblage dépend d’objdump, mais la trace reste lisible sans.

## Interaction avec la UI

La webview se base sur :

- `snapshots`: pour la pile, registres et instruction
- `meta.word_size`, `meta.buffer_offset`, `meta.buffer_size`
- `meta.disasm` et `meta.disasm_path` (si présents)
- `meta.view_mode` (static ou dynamic)

Si le mapping addr2line est présent, l’UI affiche le contexte source (ligne + fonction).

## Limites connues

- Pas de modèle mémoire complet : pas d’aliasing, pas de protections, pas de paging.
- Émulation très minimaliste des syscalls.
- Pas de support pour les instructions spécifiques à certains CPU (selon Unicorn).
- Les programmes auto-modifiants ou anti-émulation peuvent échouer.

## Pistes d’amélioration

- Émuler un sous-ensemble de syscalls supplémentaires (write, exit, mmap).
- Ajouter un modèle de heap minimal (malloc/free simulés).
- Ajouter la gestion d’auxv plus complète et envp.
- Ajouter un loader ELF plus robuste (relocations basiques).
