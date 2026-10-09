# Scénario de démonstration TriageX (3 builds)

Ce dossier contient la version corrigée de l'application, utilisée à l'étape 3.
Il est volontairement **en dehors** de `demo-app/` pour ne pas être analysé par les scanners.

## Build 1 : bloqué par un secret

État initial du dépôt. Gitleaks trouve le jeton écrit en dur dans `demo-app/app.py` :
le quality gate bloque, rien n'est déployé.

## Build 2 : le secret est retiré, mais l'image reste dangereuse

```bash
sed -i '/^API_TOKEN = /d' demo-app/app.py
git commit -am "Démo étape 2 : retrait du secret" && git push
```

Le secret a disparu, mais l'image de base `python:3.8-slim` (Python en fin de vie) contient
une vulnérabilité critique : le quality gate bloque encore, rien n'est déployé.

## Build 3 : image et dépendances corrigées, déploiement automatique

```bash
cp demo-steps/secure/Dockerfile demo-steps/secure/requirements.txt demo-app/
git commit -am "Démo étape 3 : image Alpine récente, dépendances à jour, utilisateur non-root" && git push
```

Le quality gate est validé : Jenkins exporte l'image analysée et Ansible la déploie sur
ai-app (http://192.168.138.11:3000), avec contrôle de santé et retour arrière automatique.

Les failles volontaires du code (injection SQL, `eval`...) restent signalées en priorité haute
dans le rapport : le quality gate ne bloque que les risques critiques. C'est pourquoi le
conteneur de l'application est enfermé (non-root, lecture seule, aucune capacité Linux,
réseau isolé des services internes).

## Revenir à l'état initial (pour rejouer la démo)

```bash
git log --oneline -5          # repérer le commit avant "Démo étape 2"
git revert --no-edit HEAD HEAD~1 && git push
```
