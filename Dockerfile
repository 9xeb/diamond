FROM debian:stable

# TODO: handle requirements/dependencies in a dynamic way

# IOC dependencies
RUN apt update && apt upgrade -y && apt install -y python3-pip file crowdsec jq curl sqlite3
RUN pip3 install redis sqlalchemy cortex4py pymispwarninglists elasticsearch elasticsearch_follow regex sqlalchemy-views PyMySQL psycopg2-binary cachetools OTXv2
#elasticsearch==7.13.3
# SIGMA dependencies
RUN apt-get update && apt-get -y upgrade && apt-get -y install python3-pip pipenv git parallel 
# NOTE: elasticsearch-dsl downgrades elasticsearch to 7.17.7
RUN python3 -m pip install pyyaml elasticsearch sigmatools elasticsearch-dsl sqlalchemy PyMySQL psycopg2-binary
#elasticsearch==7.13.3
# Main script
COPY ./docker-entrypoint.sh /docker-entrypoint.sh

# IOC files
COPY ./elastic_to_threatintel.py /threatintel/elastic_to_threatintel.py
COPY ./ioc_correlation_engine/ioc_correlation_engine.py /threatintel/ioc_correlation_engine.py
COPY ./ioc_correlation_engine/handlers/handler.py /threatintel/handlers/handler.py
COPY ./ioc_correlation_engine/handlers/abusech.py /threatintel/handlers/abusech.py
COPY ./ioc_correlation_engine/handlers/misp-warninglist.py /threatintel/handlers/misp-warninglist.py
COPY ./ioc_correlation_engine/handlers/alienvault-otx.py /threatintel/handlers/alienvault-otx.py

RUN mkdir /threatintel/data/
COPY ./setup-crowdsec.sh /setup-crowdsec.sh
COPY ./push-to-crowdsec.sh /push-to-crowdsec.sh
RUN useradd -ms /bin/bash threatintel && chmod +x /setup-crowdsec.sh && chmod +x /push-to-crowdsec.sh && chmod +x /threatintel/elastic_to_threatintel.py && chmod +x ./threatintel/handlers/* && chown -R threatintel:threatintel /threatintel
#WORKDIR /threatintel/
#CMD /setup-crowdsec.sh && python3 ./elastic_to_threatintel.py | tee -a /threatintel/data/alerts.log | /push-to-crowdsec.sh

# SIGMA files
#COPY ./sigma_engine/generate_sigma_rules.sh /threatintel/generate_sigma_rules.sh
#COPY ./sigma_engine/sigma_engine.py /threatintel/sigma_engine.py
#COPY ./sigma_engine/nsm_and_web.yml /threatintel/nsm_and_web.yml
#COPY ./sigma_engine/linux_auditd.yml /threatintel/linux_auditd.yml


ENTRYPOINT ["/bin/bash", "/docker-entrypoint.sh"]
