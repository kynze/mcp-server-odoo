# ruff: noqa: F821  (env is the odoo shell global)
# Run via: odoo shell -d e2e --no-http < setup_odoo.py
import datetime

alice = env["res.users"].create(
    {
        "name": "Alice",
        "login": "alice",
        "group_ids": [(6, 0, [env.ref("base.group_user").id])],
    }
)
exp = datetime.datetime.now() + datetime.timedelta(days=1)
for name, user in (("admin", env.ref("base.user_admin")), ("alice", alice)):
    key = env(user=user)["res.users.apikeys"]._generate("rpc", "e2e", exp)
    with open(f"/var/lib/odoo/key_{name}", "w") as f:
        f.write(key)
env.cr.commit()
print("SETUP OK")
