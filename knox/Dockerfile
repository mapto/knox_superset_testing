FROM openjdk:8-jre-alpine

RUN apk --no-cache add bash procps wget ca-certificates && update-ca-certificates
RUN adduser -S knox

ARG KNOX_VERSION=1.2.0

ENV GATEWAY_HOME /knox

COPY knox-${KNOX_VERSION}.zip /knox-${KNOX_VERSION}.zip

# RUN wget -q -O /knox-${KNOX_VERSION}.zip https://dist.apache.org/repos/dist/release/knox/${KNOX_VERSION}/knox-${KNOX_VERSION}.zip && unzip /knox-${KNOX_VERSION}.zip && rm knox-${KNOX_VERSION}.zip && ln -nsf /knox-${KNOX_VERSION} /knox && chmod +x /knox/bin/*.sh && chown -R knox /knox/

RUN unzip /knox-${KNOX_VERSION}.zip && rm knox-${KNOX_VERSION}.zip && ln -nsf /knox-${KNOX_VERSION} /knox && chmod +x /knox/bin/*.sh && chown -R knox /knox/

COPY gateway-site.xml /knox/conf/gateway-site.xml
COPY gateway-log4j.properties /knox/conf/gateway-log4j.properties

# ADD master /knox/data/security/master
# COPY master /knox/data/security/master
RUN /knox/bin/knoxcli.sh create-master --master knox
RUN chown -R knox /knox/data/security
RUN chown -R knox /knox/data/security/keystores

RUN chmod -R +w /knox/logs && chown -R knox /knox/logs
RUN chmod -R +w /knox/conf && chown -R knox /knox/conf

ADD ldap.sh /ldap.sh
ADD gateway.sh /gateway.sh

USER knox
WORKDIR /knox
# ENTRYPOINT ["/gateway.sh", "start"]
# ENTRYPOINT ["tail", "-f", "/dev/null"]
