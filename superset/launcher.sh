#!/bin/bash

# set -e
# set -o pipefail

set -euxo pipefail

gunicorn superset:app --access-logfile /var/log/superset.out --error-logfile /var/log/superset.err --log-level DEBUG
# gunicorn superset:app --access-logfile /var/log/superset.out --error-logfile /var/log/superset.err
# gunicorn superset:app
# gunicorn superset:app --log-level DEBUG

# tail -f /dev/null
