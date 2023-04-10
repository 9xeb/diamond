#!/bin/bash

if [ "$CROWDSEC_LAPI_URL" == "" ] || [ "$CROWDSEC_AGENT_USERNAME" == "" ] || [ "$CROWDSEC_AGENT_PASSWORD" == "" ]; then
  echo "Crowdsec credentials not set! Quitting!"
  exit 1
fi

# set credentials for reaching out to the LAPI
echo "url: ""$CROWDSEC_LAPI_URL" > /etc/crowdsec/local_api_credentials.yaml
echo "login: ""$CROWDSEC_AGENT_USERNAME" >> /etc/crowdsec/local_api_credentials.yaml
echo "password: ""$CROWDSEC_AGENT_PASSWORD" >> /etc/crowdsec/local_api_credentials.yaml
echo "[entrypoint] Crowdsec credentials set!"

# Starting the crowdsec daemon is not necessary for manual cscli operations!
#/usr/bin/crowdsec -c /etc/crowdsec/config.yaml &

while cscli lapi status &> /dev/null; ss=$?; [[ $ss -ne 0 ]]; do
  echo "[entrypoint] Local crowdsec API at ""$CROWDSEC_LAPI_URL"" is not reachable. Retrying in 5 seconds."
  sleep 5
done
echo "[entrypoint] Local crowdsec API is reachable!"

