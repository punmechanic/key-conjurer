#!/bin/sh
# /tmp/vault/secret.json is created by our extension at /opt/extensions/vault.
if [[ -z "$VAULT_ADDR" ]]; then
    # If VAULT_ADDR is not specified, we assume that the environment variables are already set.
    ./main
else
    OKTA_HOST=$(jq -r '.okta_host' /tmp/vault/secret.json)
    OKTA_TOKEN=$(jq -r '.okta_token' /tmp/vault/secret.json)
    ./main
fi
