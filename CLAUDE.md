# Règles de travail

## Livrer un changement : toujours par une PR revue

Jamais de commit ni de push directement sur `feat/oauth-multi-user`.

1. Partir de `feat/oauth-multi-user` à jour : `git switch feat/oauth-multi-user && git pull`, puis `git switch -c <type>/<sujet>` (`feat/`, `fix/`, `chore/`, `docs/`, `test/`).
2. Commiter sur la branche ; les tests passent en local : `uv run pytest -m "not yolo and not mcp"`, avec `ruff`.
3. Pousser et ouvrir la PR : `git push -u origin <branche>`, puis `gh pr create --repo kynze/mcp-server-odoo --base feat/oauth-multi-user --fill`.
4. Revue automatique : `/code-review <numéro de PR> --comment`. Corriger ce qu'elle trouve par de nouveaux commits sur la branche, relancer la revue si les corrections sont importantes.
5. Fusionner seulement avec l'accord de l'utilisateur : `gh pr merge <numéro> --repo kynze/mcp-server-odoo --rebase --delete-branch`, puis `git switch feat/oauth-multi-user && git pull`.
6. Railway déploie `feat/oauth-multi-user` : fusionner = mettre en production.

⚠️ Ce dépôt est un fork de `ivnvxd/mcp-server-odoo` : toujours passer `--repo kynze/mcp-server-odoo`, sinon `gh` ouvre la PR chez l'auteur d'origine.
