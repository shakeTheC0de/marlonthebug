#!/usr/bin/env bash
# Laboratorio desechable de práctica. Uso: scripts/lab.sh [up|tools|down|reset|status]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
COMPOSE=(docker compose -f docker-compose.lab.yml)

case "${1:-up}" in
  up)
    "${COMPOSE[@]}" up -d juice-shop webgoat
    echo "Juice Shop: http://127.0.0.1:3000"
    echo "WebGoat:    http://127.0.0.1:8080/WebGoat"
    ;;
  tools)
    "${COMPOSE[@]}" run --rm lab-tools
    ;;
  status)
    "${COMPOSE[@]}" ps
    ;;
  down)
    "${COMPOSE[@]}" down
    ;;
  reset)
    "${COMPOSE[@]}" down -v
    "${COMPOSE[@]}" up -d juice-shop webgoat
    ;;
  *)
    echo "Uso: $0 [up|tools|down|reset|status]" >&2
    exit 1
    ;;
esac
