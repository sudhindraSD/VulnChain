#!/usr/bin/env bash
# VulnChain web demo launcher — http://127.0.0.1:8000
# First time only: pip install -r webapp/requirements.txt
#                  cd webapp/frontend && npm install && npm run build
cd "$(dirname "$0")"
python server.py
