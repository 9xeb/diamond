#!/bin/bash

# Create truststore from /ca.cert
#echo yes | \
#keytool -import -file /ca.cert -alias elasticCA -storepass "$CORTEX_TRUSTSTORE_PASSWORD" -keystore /opt/cortex/CortexTrustStore || { echo "[!] Failed to import /ca.cert to custom TrustStore"; rm /opt/cortex/CortexTrustStore; };

#echo yes | \
#keytool -import -alias elasticCA -keystore "$JAVA_HOME"/jre/lib/security/cacerts -storepass changeit -file /ca.cert || { echo "[!] Failed to import /ca.cert to default TrustStore"; rm /opt/cortex/CortexTrustStore; };

# Update application.conf with custom truststore password
cp /etc/cortex/application-template.conf /etc/cortex/application.conf

#sed -i 's/search.trustStore.password.*"/search.trustStore.password = "'"$CORTEX_TRUSTSTORE_PASSWORD"'"/g' /etc/cortex/application.conf || { echo "[!] Failed to update /etc/cortex/application.conf"; rm /opt/cortex/CortexTrustStore; exit 1; }

if [[ $ELASTICSEARCH_USERNAME != "" ]] && [[ $ELASTICSEARCH_PASSWORD != "" ]]; then
   if sed -i 's/search.user.*"/search.user = "'"$ELASTICSEARCH_USERNAME"'"/g' /etc/cortex/application.conf; ss=$?; [[ $ss -ne 0 ]]; then
    echo "[!] Failed to update /etc/cortex/application.conf"; rm /opt/cortex/CortexTrustStore;
    exit 1;
   fi
   echo "Updated elastic username"
   if sed -i 's/search.password.*"/search.password = "'"$ELASTICSEARCH_PASSWORD"'"/g' /etc/cortex/application.conf; ss=$?; [[ $ss -ne 0 ]]; then
    echo "[!] Failed to update /etc/cortex/application.conf"; rm /opt/cortex/CortexTrustStore;
    exit 1;
   fi
   echo "Updated elastic password"
fi

# Run cortex app
/opt/cortex/entrypoint