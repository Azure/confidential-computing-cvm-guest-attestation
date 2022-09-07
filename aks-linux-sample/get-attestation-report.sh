#!/bin/bash

/AttestationClient

JWT=$(cat /jwt_encoded)

echo -n $JWT | cut -d "." -f 1 | base64 -d 2>/dev/null | jq .
echo -n $JWT | cut -d "." -f 2 | base64 -d 2>/dev/null | jq .
