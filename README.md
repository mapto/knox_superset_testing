# Knox/Superset Integration Test

This is an attempt to integrate KnoxSSO and Superset as per the [corresponding issue](https://issues.apache.org/jira/browse/KNOX-1783) in Apache JIRA.

It is loosely based on the examples of [KnoxSSO testing](https://github.com/lmccay/knox_sso_testing) and [Knox/Solr testing](https://github.com/risdenk/knox_solr_testing). The Superset container is loosely based on [amancevice's superset container](https://github.com/amancevice/superset) with LDAP authentication.

Still, there are a few notable differences:

* Using Knox version 1.2.0
* No KerberOS

## Installation

To setup:

    docker network create example.com

To start:

    docker-compose up -d

Access from host machine for testing purposes:

* LDAP: ldap://172.17.0.1:389
* Superset: http://172.17.0.1:8088
* Superset via Knox: https://172.17.0.1:8443

Credentials are loaded from Knox [defaults](https://github.com/apache/knox/blob/master/gateway-release/home/conf/users.ldif).
