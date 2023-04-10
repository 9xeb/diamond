#!/bin/bash

# WARNING: this script does not perform input sanitization! Make sure you give it that it expects or it might behave unexpectedly. Use ./generic-analyze.sh which wraps on this.

# This script interacts with a Cortex API and schedules analysis of observables in bulk.
# In order to fully benefit from Cortex's parallelism, scheduling is done in bulk. After that, reports are requested one by one.
# cortex4sh can be easily integrated into an automated defense pipeline, being json to json.

if [ -z ${CORTEX_APP_URL+x} ]; then
  echo "[cortex4sh] CORTEX_APP_URL env not set! Quitting." 1>&2
  exit 1
fi
#CORTEX_APP_URL="http://localhost:9001"
#CORTEX_API_KEY="nSqAzZzVUlz4fRHtcsmJFDBNNT88pLVU"
if [ -z ${CORTEX_API_KEY+x} ]; then
  echo "[cortex4sh] CORTEX_API_KEY env not set! Quitting." 1>&2
  exit 1
fi
#CORTEX_API_KEY="SFUuqrWKp0NKlGtCwkCKfYjdCAdvjQcC"
TLP=0
MINUTES_TIMEOUT=5

# list of supported observables
SUPPORTED_OBSERVABLES='ip domain hash'

# $1 -> observable type
# $2 -> analyzer id
# $3 -> observable value
function schedule {
  # Schedule single observable analysis
  if [[ $1 == "file" ]]; then
    # Files require a special treatment, some debugging is required before I implement this
    echo "[*] Files are not supported yet"
    #curl -X POST -H 'Authorization: Bearer '"$CORTEX_API_KEY" -H 'Content-Type: application/json' "$CORTEX_API_URL"'/api/analyzer/'"$analyzer"'/run' \
    #     -F 'attachment=@'"$observable" \
    #     -F '_json=<-;type=application/json' << _EOF_
    #     {
    #     "dataType":"file",
    #     "tlp":0
    #     }
    #_EOF_
  else
    curl -s -XPOST -H 'Authorization: Bearer '"$CORTEX_API_KEY" -H 'Content-Type: application/json' "$CORTEX_APP_URL"'/api/analyzer/'"$2"'/run' \
         -d '{
           "data":"'"$3"'",
           "dataType":"'"$1"'",
           "tlp":'"$TLP"',
           "message": "Scheduled by cortex4sh."
         }' | jq '.id' | cut -d\" -f 2
  fi
}

function live_analyze_cmdline {
  # WARNING: this script trusts user input, do not run directly. Run generic-analyze.sh instead.
  # TODO: build analyzer id list from supported observables beforehand. This will reduce the number of API calls to cortex, but it also will require this script to restart if someone reconfigures new cortex analyzers.
  while IFS= read -r observable_json; do
    host=$(echo "$observable_json" | jq '.host' | cut -d'"' -f2)
    type=$(echo "$observable_json" | jq '.type' | cut -d'"' -f2)
    observable=$(echo "$observable_json" | jq '.value' | cut -d'"' -f2)
    timestamp=$(echo "$observable_json" | jq '.timestamp' | cut -d'"' -f2)
    #printf "type: %s, value: %s\n" "$type" "$observable"
    #continue

    if [[ SECONDS -gt 60 ]] then
      refresh_analyzers $type
    fi
    reports=$(for analyzer in ${[@]}; do schedule "$type" "$analyzer" "$observable"; done)

    echo "[cortex4sh] Scheduled analysis for ""$observable" 1>&2
    for report_id in $reports; do
      curl -s -H 'Authorization: Bearer '"$CORTEX_API_KEY" "$CORTEX_APP_URL"'/api/job/'"$report_id"'/waitreport?atMost='"$MINUTES_TIMEOUT"'minute'
    done | \
    jq -c '. += { "host": "'""$host""'" }' | \
    jq -c '. += { "value": "'""$observable""'" }' | \
    jq -c '. += { "type": "'"$type"'" }' | \
    jq -c '. += { "timestamp": "'"$timestamp"'" }'
    #jq -c '.report | .full' | \
    #jq -c -n '.full |= [inputs]' | \
  done
}

function refresh_analyzers {
  analyzers[$1]=()
  for analyzer in $(curl -s -H 'Authorization: Bearer '"$CORTEX_API_KEY" "$CORTEX_APP_URL"'/api/analyzer/type/'"$1" | jq -c '.[] | .id' | cut -d\" -f 2)
    analyzers[$1]+=( "$analyzer" )
  done
  SECONDS=0
  ${tail_params[@]}
}

declare -A analyzers
declare -A analyzers_timeouts
# set seconds so that
SECONDS=61
live_analyze_cmdline
echo "[cortex4sh] I just crashed!" 1>&2
# > cortex4sh.log
