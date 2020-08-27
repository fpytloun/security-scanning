FROM aquasec/trivy AS trivy

FROM owasp/dependency-check
USER root

ENV PYTHONUNBUFFERED 1

RUN apk add --no-cache -X http://dl-cdn.alpinelinux.org/alpine/edge/testing -X http://dl-cdn.alpinelinux.org/alpine/edge/community podman httpie jq python3 py3-tz curl ca-certificates git rpm go
RUN pip3 install elasticsearch boto3 PyYAML

ADD secscan.py /usr/local/bin/secscan
RUN ln -s /usr/local/bin/secscan /usr/local/bin/trivy-report && \
    ln -s /usr/local/bin/secscan /usr/local/bin/depcheck-report

# Trivy
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
RUN trivy image --download-db-only --no-progress

# Depcheck
RUN ln -s /usr/share/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check
#USER dependencycheck
RUN dependency-check --updateonly

ENTRYPOINT ["/usr/local/bin/secscan"]
