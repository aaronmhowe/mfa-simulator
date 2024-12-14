#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

rm -f "$SCRIPT_DIR/db/auth.db"
rm -f "$SCRIPT_DIR/db/secrets.db"

echo "Removed User Credentials and Secrets"