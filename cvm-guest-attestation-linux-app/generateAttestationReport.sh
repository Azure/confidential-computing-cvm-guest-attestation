#!/bin/bash
JWT=`cat jwt_encoded`
for line in `echo $JWT | tr "." "\n"`; do echo $line | base64 --decode | jq  && echo;done
