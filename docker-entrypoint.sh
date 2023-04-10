#!/bin/bash

#/bin/bash /threatintel/generate_sigma_rules.sh

cd /threatintel
#/setup-crowdsec.sh &&
find /logs/ -type f -name "*" | xargs tail -q -F | strings | python3 /threatintel/elastic_to_threatintel.py | tee -a /threatintel/data/alerts.log
# | /push-to-crowdsec.sh

