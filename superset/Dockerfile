FROM python:3.6

# Superset version
ARG SUPERSET_VERSION=0.29.0rc7

# Configure environment
ENV GUNICORN_BIND=0.0.0.0:8088 \
    GUNICORN_LIMIT_REQUEST_FIELD_SIZE=0 \
    GUNICORN_LIMIT_REQUEST_LINE=0 \
    GUNICORN_TIMEOUT=60 \
    GUNICORN_WORKERS=2 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONPATH=/etc/superset:/home/superset:$PYTHONPATH \
    SUPERSET_REPO=apache/incubator-superset \
    SUPERSET_VERSION=${SUPERSET_VERSION} \
    SUPERSET_HOME=/var/lib/superset
ENV GUNICORN_CMD_ARGS="--workers ${GUNICORN_WORKERS} --timeout ${GUNICORN_TIMEOUT} --bind ${GUNICORN_BIND} --limit-request-line ${GUNICORN_LIMIT_REQUEST_LINE} --limit-request-field_size ${GUNICORN_LIMIT_REQUEST_FIELD_SIZE}"

COPY requirements.txt .

# Create superset user & install dependencies
RUN useradd -U -m superset && \
    mkdir /etc/superset  && chown -R superset:superset /etc/superset && \
    mkdir ${SUPERSET_HOME} && chown -R superset:superset ${SUPERSET_HOME} && \
    apt-get update && \
    apt-get install -y \
        build-essential \
        curl \
        mlocate \
        # default-libmysqlclient-dev \
        # freetds-dev \
        # freetds-bin \
        # libffi-dev \
        # libpq-dev \
        libssl1.0 \
        libsasl2-dev \
        libldap2-dev && \
    apt-get clean && rm -r /var/lib/apt/lists/* && \
    curl https://raw.githubusercontent.com/${SUPERSET_REPO}/${SUPERSET_VERSION}/requirements.txt -o requirements.superset.txt && \
    pip install --no-cache-dir -r requirements.superset.txt && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir superset==${SUPERSET_VERSION} && \
    rm requirements.*

# Configure Filesystem
COPY config.py /usr/local/lib/python3.6/site-packages/superset
COPY knox_auth.py /usr/local/lib/python3.6/site-packages/superset
COPY __init__.py /usr/local/lib/python3.6/site-packages/superset
COPY launcher.sh /

VOLUME /home/superset \
       /etc/superset \
       /etc/ssl/keystores \
       /var/lib/superset \
       /var/log

WORKDIR /home/superset

COPY superset.db /var/lib/superset

# COPY superset-init /usr/local/bin

# RUN ["/usr/local/bin/superset-init", "--username", "root", "--firstname", "root", "--lastname", "root", "--email", "root@example.com", "--password", "root-password"]

# Deploy application
EXPOSE 8088
HEALTHCHECK CMD ["curl", "-f", "http://localhost:8088/health"]
# ENTRYPOINT ["gunicorn", "superset:app", "--access-logfile", "/var/log/superset.out", "--error-logfile", "/var/log/superset.err", "--log-level", "DEBUG"]
# ENTRYPOINT ["gunicorn", "superset:app", "--access-logfile", "/var/log/superset.out", "--error-logfile", "/var/log/superset.err"]
CMD ["tail", "-f", "/dev/null"]
