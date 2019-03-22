#!/bin/bash

set -euxo pipefail

#java -Dorg.apache.logging.log4j.simplelog.StatusLogger.level=DEBUG -Dlog4j2.debug=DEBUG -DconfigurationFile=/knox/conf/gateway-log4j.properties -jar /knox/bin/gateway.jar >>/knox/logs/knox.out 2>>/knox/logs/knox.err
java -DconfigurationFile=/knox/conf/gateway-log4j.properties -jar /knox/bin/gateway.jar >>/knox/logs/knox.out 2>>/knox/logs/knox.err

