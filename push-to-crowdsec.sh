#!/bin/bash

while IFS= read -r line; do
  scope='IOC'
  scope=$(echo $line | jq '.scope' | cut -d'"' -f 2)
  value=$(echo "$line" | jq '.value' | cut -d'"' -f 2)
  reason=$(echo "$line" | jq '.reason' | cut -d'"' -f 2)

  #if cscli decisions list -o json | jq '.[].source.value' | cut -d'"' -f 2 | grep '^'"$value" > /dev/null; ss=$?; [ $ss -ne 0 ]; then
  if cscli decisions add --scope "$scope" --value "$value" --reason "$reason" --type 'record' --duration 24h 2> /dev/null; ss=$?; [ $ss -eq 0 ]; then
    echo "[reported] ""$value"" (""$scope"")" 2>&1
  else
    echo "[ERROR] Failed to push to crowdsec" 2>&1
  fi
  #fi
done