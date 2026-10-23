# Règles de travail

## Livrer un changement : toujours par une PR revue

Jamais de commit ni de push directement sur `feat/oauth-multi-user`.

1. Dans le dossier principal du dépôt (pas dans un worktree : les fichiers ignorés par git n'y sont pas), créer la branche depuis `feat/oauth-multi-user` à jour : `git fetch origin && git switch --no-track -c <type>/<sujet> origin/feat/oauth-multi-user` (`feat/`, `fix/`, `chore/`, `docs/`, `test/`, `ci/`).
2. Commiter sur la branche ; les tests passent en local : `uv run pytest -m "not yolo and not mcp"`, avec `ruff`.
3. Pousser et ouvrir la PR : `git push -u origin <branche>`, puis `gh pr create --repo kynze/mcp-server-odoo --base feat/oauth-multi-user --title "<type>: <résumé>" --body "<quoi et pourquoi>"`, le corps terminé par la ligne d'attribution.
4. Revue de code : `/code-review <numéro de PR> high --comment`.
5. Revue de simplicité : `/ponytail-review` sur le diff de la PR, `git diff origin/feat/oauth-multi-user...HEAD` (skill ponytail : ce qu'on peut supprimer ou simplifier).

   Pour les deux revues : vérifier chaque remarque avant d'agir. Corriger celles qui sont fondées par de nouveaux commits **poussés** (`git push`), répondre aux autres dans la PR en disant pourquoi. Ponytail n'écrit rien dans la PR : y poster ses remarques et la suite donnée (`gh pr comment`). Après de grosses corrections, relancer `/code-review <numéro de PR> high` sans `--comment` (pas de commentaires en double).
6. Attendre la CI verte sur la PR : `gh pr checks <numéro> --repo kynze/mcp-server-odoo --watch`. Puis fusionner, seulement avec l'accord de l'utilisateur, depuis la branche de la PR : `gh pr merge <numéro> --repo kynze/mcp-server-odoo --squash --delete-branch` (un seul commit par PR ; bascule sur `feat/oauth-multi-user` à jour et supprime la branche ; vérifier avec `git status -sb`).
7. Railway déploie `feat/oauth-multi-user` : fusionner = mettre en production.

⚠️ Ce dépôt est un fork de `ivnvxd/mcp-server-odoo` : toujours passer `--repo kynze/mcp-server-odoo`, sinon `gh` ouvre la PR chez l'auteur d'origine.
