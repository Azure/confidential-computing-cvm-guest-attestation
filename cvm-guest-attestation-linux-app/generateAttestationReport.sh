#!/bin/bash

function jwt-decode() {
  sed 's/\./\n/g' <<< $(cut -d. -f1,2 <<< $1) | base64 --decode | jq
}

JWT=`cat jwt_encoded`

jwt-decode $JWT > maa_report.json
