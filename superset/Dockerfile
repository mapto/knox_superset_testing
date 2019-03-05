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

# Create superset user & install dependencies
RUN useradd -U -m superset && \
    mkdir /etc/superset  && chown -R superset:superset /etc/superset && \
    mkdir ${SUPERSET_HOME} && chown -R superset:superset ${SUPERSET_HOME} && \
    apt-get update && \
    apt-get install -y \
        build-essential \
        curl \
        # default-libmysqlclient-dev \
        # freetds-dev \
        # freetds-bin \
        # libffi-dev \
        # libpq-dev \
        libssl1.0 \
        libsasl2-dev \
        libldap2-dev && \
    apt-get clean && rm -r /var/lib/apt/lists/* && \
    curl https://raw.githubusercontent.com/${SUPERSET_REPO}/${SUPERSET_VERSION}/requirements.txt -o requirements.txt && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir \
        # Werkzeug==0.14.1 \
        # flask-cors==3.0.3 \
        # flask-mail==0.9.1 \
        # gevent==1.2.2 \
        # impyla==0.14.0 \
        # infi.clickhouse-orm==1.0.2 \
        # mysqlclient==1.3.7 \
        # psycopg2==2.6.1 \
        # pyathena==1.2.5 \
        # pyhive==0.5.1 \
        pyldap==2.4.28 \
        # redis==2.10.5 \
        # sqlalchemy-clickhouse==0.1.5.post0 \
        # sqlalchemy-redshift==0.7.1 \
        superset==${SUPERSET_VERSION} && \
    rm requirements.txt

# Configure Filesystem
COPY superset-init /usr/local/bin
# COPY superset-demo /usr/local/bin
COPY config.py /usr/local/lib/python3.6/site-packages/superset
VOLUME /home/superset \
       /etc/superset \
       /var/lib/superset \
       /var/log
WORKDIR /home/superset

RUN ["/usr/local/bin/superset-init", "--username", "root", "--firstname", "root", "--lastname", "root", "--email", "cons.ruskovmartin@sia.eu", "--password", "root-password"]

# Deploy application
EXPOSE 8088
HEALTHCHECK CMD ["curl", "-f", "http://localhost:8088/health"]
# ENTRYPOINT ["gunicorn", "superset:app", "--access-logfile", "/var/log/superset.out", "--error-logfile", "/var/log/superset.err", "--log-level", "DEBUG"]
ENTRYPOINT ["gunicorn", "superset:app", "--access-logfile", "/var/log/superset.out", "--error-logfile", "/var/log/superset.err"]
