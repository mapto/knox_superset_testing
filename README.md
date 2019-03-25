# Knox/Superset Integration Test

This is an attempt to integrate KnoxSSO and Superset as per the corresponding issues in [Knox JIRA](https://issues.apache.org/jira/browse/KNOX-1783) and [Superset Github](https://github.com/apache/incubator-superset/issues/7024).

It is loosely based on the examples of [KnoxSSO testing](https://github.com/lmccay/knox_sso_testing) and [Knox/Solr testing](https://github.com/risdenk/knox_solr_testing). The Superset container is loosely based on [amancevice's superset container](https://github.com/amancevice/superset) with LDAP authentication.

Still, there are a few notable differences:

* Using Knox version 1.2.0
* Utilising [hadoop-jwt](https://svn.apache.org/repos/asf/knox/site/books/knox-1-2-0/knoxsso_integration.html) cookie.
* No KerberOS

## Installation

To setup:

    docker network create example.com

To start:

    docker-compose up -d

Access from host machine for testing purposes:

* LDAP: ldap://172.17.0.1:389
* Superset: http://172.17.0.1:8088 - available only for testing purposes, not functional unless `hadoop-jwt` cookie manually injected.
* Superset via federation (KnoxSSO): https://172.17.0.1:8443/gateway/sandbox/superset/
* Proxying a dummy Flask-AppBuilder service (e.g. from this [repository](https://github.com/mapto/Flask-AppBuilder-Auth-test#hadoop-jwt)): https://172.17.0.1:8443/gateway/sandbox/dummy/

Credentials are loaded from Knox [defaults](https://github.com/apache/knox/blob/master/gateway-release/home/conf/users.ldif).
