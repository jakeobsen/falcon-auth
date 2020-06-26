#!/bin/bash
export JWT_PUBKEY=$(cat jwtRS256.key.pub)
export JWT_PRIVKEY=$(cat jwtRS256.key)
export MYSQL_PORT="3306"
export MYSQL_USER=""
export MYSQL_PASSWORD=""
export MYSQL_HOST="localhost"
export MYSQL_DATABASE=""
export REDIS_HOST="localhost"
export REDIS_PORT="6379"
export REDIS_DB="0"

. venv/bin/activate

echo "Now you can run: gunicorn --reload main:api"