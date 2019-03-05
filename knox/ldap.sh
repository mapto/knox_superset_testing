#!/bin/bash

# set -e
# set -o pipefail

set -euxo pipefail

java -jar /knox/bin/ldap.jar /knox/conf

