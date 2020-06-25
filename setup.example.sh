#!/bin/bash
export JWT_PUBKEY=$(cat jwtRS256.key.pub)
export JWT_PRIVKEY=$(cat jwtRS256.key)
export MYSQL_PORT="3306"
export MYSQL_USER=""
export MYSQL_PASSWORD=""
export MYSQL_HOST="localhost"
export MYSQL_DATABASE=""

. venv/bin/activate

echo "Now you can run: gunicorn --reload main:api"