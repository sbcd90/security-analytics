ARG DOCKER_VERSION_ARG
FROM opensearchstaging/opensearch:${DOCKER_VERSION_ARG}
#FROM phaseshiftstudio/opensearch:2.4.0-old-with-security
SHELL ["/bin/bash","-x","-e","-c"]
ARG PLUGIN_ARG
ENV PLUGIN ${PLUGIN_ARG}
RUN if [ -d /usr/share/opensearch/plugins/opensearch-security-analytics ]; then /usr/share/opensearch/bin/opensearch-plugin remove opensearch-security-analytics; fi;

ADD build/distributions/$PLUGIN /tmp/
ADD ./ /opt/opensearch-security-analytics
USER root
COPY --chown=opensearch:opensearch src/test/resources/sample.pem /usr/share/opensearch/config/sample.pem
COPY --chown=opensearch:opensearch src/test/resources/test-kirk.jks /usr/share/opensearch/config/test-kirk.jks
RUN chown -R opensearch:opensearch /opt/opensearch-security-analytics
USER opensearch
RUN /usr/share/opensearch/bin/opensearch-plugin install --batch file:/tmp/$PLUGIN