#FROM thehiveproject/cortex:3.1.0-1
FROM thehiveproject/cortex:latest

COPY ./setup.sh /opt/cortex/setup.sh
RUN chmod +x /opt/cortex/setup.sh
ENTRYPOINT [ "/opt/cortex/setup.sh" ]
#ENTRYPOINT ["sleep inf"]
#USER root
#RUN apt update && apt-get install -y --no-install-recommends git python-pip python2.7-dev python3-pip python3-dev ssdeep libfuzzy-dev libfuzzy2 libimage-exiftool-perl libmagic1 build-essential git libssl-dev && pip install -U pip setuptools && pip3 install -U pip setuptools
#RUN git clone https://github.com/TheHive-Project/Cortex-Analyzers
#RUN mv ./Cortex-Analyzers/analyzers /opt/cortex/analyzers && mv ./Cortex-Analyzers/responders /opt/cortex/responders && rm -rf ./Cortex-Analyzers
#RUN for I in $(find analyzers -name 'requirements.txt'); do pip2 install -r $I; done && \
#    for I in $(find analyzers -name 'requirements.txt'); do pip3 install -r $I || true; done
#RUN for I in $(find responders -name 'requirements.txt'); do pip2 install -r $I; done && \
#    for I in $(find responders -name 'requirements.txt'); do pip3 install -r $I || true; done

# Embed MISP warning lists to filter out false positives
#RUN git clone https://github.com/MISP/misp-warninglists && mv ./misp-warninglists/lists /misp-warninglists && rm -rf ./misp-warninglists
#USER daemon
