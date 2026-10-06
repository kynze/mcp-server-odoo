#!/usr/bin/env bash
# E2E: multi-user OAuth against a real Odoo 20 in Docker.
set -euo pipefail
export MSYS_NO_PATHCONV=1
P=mcp-oauth-e2e
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PG_ENV=(-e HOST=$P-pg -e USER=odoo -e PASSWORD=odoo)

cleanup() {
  docker rm -f $P-srv $P-odoo $P-pg >/dev/null 2>&1 || true
  docker network rm $P >/dev/null 2>&1 || true
  docker volume rm $P-data >/dev/null 2>&1 || true
  docker rmi -f $P >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker network create $P >/dev/null
docker volume create $P-data >/dev/null
docker run -d --name $P-pg --network $P -e POSTGRES_USER=odoo -e POSTGRES_PASSWORD=odoo -e POSTGRES_DB=postgres postgres:16 >/dev/null
until docker exec $P-pg pg_isready -U odoo >/dev/null 2>&1; do sleep 1; done

ODOO=(docker run --rm -i --network $P "${PG_ENV[@]}" -v $P-data:/var/lib/odoo odoo:20.0)
out=$("${ODOO[@]}" odoo -d e2e -i base --without-demo=all --stop-after-init 2>&1) || { echo "$out" | tail -30; exit 1; }
out=$("${ODOO[@]}" odoo shell -d e2e --no-http < "$HERE/setup_odoo.py" 2>&1) || true
grep -q "SETUP OK" <<<"$out" || { echo "$out" | tail -30; exit 1; }

docker run -d --name $P-odoo --network $P "${PG_ENV[@]}" -v $P-data:/var/lib/odoo odoo:20.0 \
  odoo -d e2e --db-filter='^e2e$' --no-database-list --http-interface=0.0.0.0 >/dev/null
ready=
for _ in $(seq 90); do
  docker exec $P-odoo python3 -c "import urllib.request as u;u.urlopen('http://localhost:8069/web/login')" >/dev/null 2>&1 && { ready=1; break; }
  sleep 2
done
[ -n "$ready" ] || { echo "Odoo not ready"; docker logs --tail 50 $P-odoo; exit 1; }

cd "$ROOT"
docker build -q -t $P . >/dev/null
docker run -d --name $P-srv --network $P --user 0 -v $P-data:/data:ro \
  -e ODOO_URL=http://$P-odoo:8069 -e ODOO_DB=e2e -e ODOO_USER=admin \
  -e ODOO_YOLO=read -e ODOO_MCP_TRANSPORT=streamable-http -e ODOO_MCP_HOST=0.0.0.0 \
  -e ODOO_MCP_PORT=8000 -e ODOO_MCP_PUBLIC_URL=http://localhost:8000 \
  -e ODOO_MCP_SECRET_KEY="$(head -c 32 /dev/urandom | base64)" -e ODOO_MCP_AUTH_TOKENS=static-e2e \
  --entrypoint sh $P -c 'ODOO_API_KEY=$(cat /data/key_admin) exec mcp-server-odoo' >/dev/null

docker cp tests/docker/oauth_e2e/client.py $P-srv:/tmp/client.py
for u in admin alice; do
  docker exec $P-srv sh -c "cp /data/key_$u /tmp/key_$u"
done
ready=
for _ in $(seq 30); do
  docker exec $P-srv python -c "import urllib.request as u;u.urlopen('http://localhost:8000/.well-known/oauth-authorization-server')" >/dev/null 2>&1 && { ready=1; break; }
  sleep 1
done
[ -n "$ready" ] || { echo "MCP server not ready"; docker logs --tail 50 $P-srv; exit 1; }
docker exec $P-srv python /tmp/client.py
echo "E2E OK"
