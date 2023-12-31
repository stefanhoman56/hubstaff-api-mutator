#!/bin/bash -e

# Update PATH in case docker-compose is installed via PIP
# and this script was invoked from e.g. cron
PATH=/usr/local/sbin:/usr/local/bin:$PATH

if [ "$(basename "$0")" == 'bin' ]; then
  cd ..
fi

. .env

target="db_dump_$(date +%Y-%m-%d_%H%M%S).sql.gz"
if [ -n "$DATABASE_URL" ]; then
  docker run --rm postgres:9.6 pg_dump -d "$DATABASE_URL" | gzip > "$target"
else
  docker-compose exec db pg_dumpall -c -U postgres | gzip > "$target"
fi

echo "$target"
