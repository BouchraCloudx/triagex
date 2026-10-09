# Application de démonstration TriageX

**Application VOLONTAIREMENT vulnérable. Ne jamais la déployer.**

Elle sert d'examen pour mesurer la précision du moteur IA de TriageX.
Elle contient de vraies failles et des pièges (du code qui ressemble à une faille mais qui est sûr).

Le code ne contient volontairement aucun commentaire qui indiquerait où sont les failles :
le moteur envoie les lignes de code à l'IA, qui pourrait sinon lire la réponse.

La correction (quelle fonction est vulnérable, laquelle est sûre, et pourquoi) se trouve dans
`evaluation/ground_truth.json`, que l'IA ne voit jamais.
