#!/bin/bash

/AttestationClient >> /attestation_output

OUTPUT=$(cat /attestation_output)
JWT=$(echo -n $OUTPUT | rev | cut -d " " -f1 | rev)

echo -n $JWT | cut -d "." -f 1 | base64 -d 2>/dev/null | jq .
echo -n $JWT | cut -d "." -f 2 | base64 -d 2>/dev/null | jq .
