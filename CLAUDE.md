# Règles de travail

## Livrer un changement : toujours par une PR revue

Jamais de commit ni de push directement sur `feat/oauth-multi-user`.

1. Créer la branche depuis `feat/oauth-multi-user` à jour (marche aussi dans un worktree) : `git fetch origin && git switch -c <type>/<sujet> origin/feat/oauth-multi-user` (`feat/`, `fix/`, `chore/`, `docs/`, `test/`, `ci/`).
2. Commiter sur la branche ; les tests passent en local : `uv run pytest -m "not yolo and not mcp"`, avec `ruff`.
3. Pousser et ouvrir la PR : `git push -u origin <branche>`, puis `gh pr create --repo kynze/mcp-server-odoo --base feat/oauth-multi-user --title "<type>: <résumé>" --body "<quoi et pourquoi>"`, le corps terminé par la ligne d'attribution.
4. Revue automatique : `/code-review <numéro de PR> high --comment`. Vérifier chaque remarque : corriger les vraies par de nouveaux commits **poussés** (`git push`), répondre aux autres dans la PR en disant pourquoi. Après de grosses corrections, relancer `/code-review <numéro de PR> high` sans `--comment` (pas de commentaires en double).
5. Fusionner seulement avec l'accord de l'utilisateur, depuis la branche de la PR : `gh pr merge <numéro> --repo kynze/mcp-server-odoo --rebase --delete-branch` (bascule sur `feat/oauth-multi-user` à jour et supprime la branche ; vérifier avec `git status -sb`).
6. Railway déploie `feat/oauth-multi-user` : fusionner = mettre en production.

⚠️ Ce dépôt est un fork de `ivnvxd/mcp-server-odoo` : toujours passer `--repo kynze/mcp-server-odoo`, sinon `gh` ouvre la PR chez l'auteur d'origine.
