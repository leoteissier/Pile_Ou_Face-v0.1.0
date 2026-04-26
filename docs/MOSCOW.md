# Priorisation MOSCOW — Pile ou Face

Ce document classe les fonctionnalités du projet selon la méthode **MOSCOW** (Must / Should / Could / Won’t). Il sert de référence pour les choix de développement et pour la soutenance.

## UI Hub (alignée MOSCOW)

L'extension expose un **hub unique** via `Pile ou Face: Ouvrir` :

| Section | MOSCOW | Contenu |
|---------|--------|---------|
| **Dashboard** | M | Point d'entrée, actions rapides (Static, Dynamic) |
| **Static (Cutter)** | M | Ouvrir binaire, désassemblage sans exécution |
| **Dynamic (GDB)** | M | Trace Unicorn, injection mémoire |
| **Outils** | S | Calculette d'offset (hex↔décimal, base+offset), recherche de strings |
| **Fichiers générés** | M | Liste, actualiser, nettoyer |

---

## M — Must have (obligatoire)

*Ce sans quoi le projet ne fonctionne pas.*

### Types de fichiers supportés

- **.exe** — binaires Windows (cible long terme).
- **.bin** — binaires bruts (ELF, raw).
- **Code source** — C, Rust, Python (analyse / génération asm ou trace).

### Compatibilité et environnement

- **Compatibilité libc** — reconnaissance des appels standards (libc).
- **Différenciation code / librairie** — distinguer le code utilisateur des bibliothèques dans les traces et le désassemblage.
- **Support binaire statique** — analyse statique (listing asm, simulation pile) sans exécution.
- **Identification statique vs dynamique** — le système distingue clairement le mode statique du mode dynamique (Unicorn).
- **Fonctionne sur Windows** — chemins Windows et compatibilité de l’extension VS Code sous Windows.
- **Gestion des fichiers générés** :
  - stockage structuré (exports, graphes, résultats) ;
  - nettoyage / suppression ;
  - réutilisation des résultats sans relancer toute l’analyse.

---

## S — Should have (important)

*Fonctionnalités importantes pour l’analyse et le confort.*

### MCP et commandes

- **MCP** — point d’entrée unique pour les fonctionnalités.
- Centralisation des commandes (extension VS Code, CLI, ou futur MCP).

### Outils d’analyse

- **Calculette d’offset** :
  - conversion hex ↔ décimal ;
  - offset ↔ adresse ;
  - aide à la navigation (pile, buffer).
- **Recherche de strings** — strings lisibles dans le binaire, avec filtrage basique.

### Visualisation

- **Visual graph** — graphe des relations (appels, flux) :
  - représentation graphique des relations ;
  - navigation dans le graphe ;
  - zoom / déplacement ;
  - lisibilité des connexions.

---

## C — Could have (optionnel)

*Utile mais non indispensable au MVP.*

- **Injecteur de code** — utilisation encadrée (tests, démonstrations), injection contrôlée ; pas obligatoire au fonctionnement global.
- **Mode expert** — activation manuelle, avec avertissement utilisateur (fonctionnalités avancées / pwn).

---

## W — Won’t have (pas pour cette version)

*Idées volontairement repoussées.*

### Personnalisation avancée

- **Customisation complète de la pile graphique** — thèmes personnalisés, disposition avancée, modification du rendu graphique.
- **Personnalisation utilisateur poussée** — profils, presets graphiques.

### Effets visuels

- **Optimisation esthétique avancée** — animations, effets visuels complexes.

---

## Lecture « projet » (soutenance)


| Priorité | Interprétation                                                                           |
| -------- | ---------------------------------------------------------------------------------------- |
| **M**    | Le projet fonctionne techniquement.                                                      |
| **S**    | Le projet devient exploitable (analyse, confort).                                        |
| **C**    | Le projet devient intéressant (extensions optionnelles).                                 |
| **W**    | Le projet pourrait devenir plus professionnel, mais c’est hors scope pour cette version. |


