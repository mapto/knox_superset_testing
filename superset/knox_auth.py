"""The necessary logic for parsing the hadoop-jwt cookie.
Further details: https://svn.apache.org/repos/asf/knox/site/books/knox-1-2-0/knoxsso_integration.html
"""
import base64
import jwt
import jks
from OpenSSL import crypto
from OpenSSL._util import lib as cryptolib
import ldap

from flask import g, redirect, request, flash
from flask_login import login_user, logout_user
from flask_appbuilder import expose
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.views import AuthLDAPView

from superset import security_manager
from superset.security import SupersetSecurityManager

import logging
log = logging.getLogger(__name__)

from . import config

jks_file = "/etc/ssl/keystores/gateway.jks"

def pem_publickey(pkey):
    """ Format a public key as a PEM. From https://stackoverflow.com/a/30929459/1827854"""
    bio = crypto._new_mem_buf()
    cryptolib.PEM_write_bio_PUBKEY(bio, pkey._pkey)
    return crypto._bio_to_string(bio)

def open_jks(jks_file):
    ks = jks.KeyStore.load(jks_file, config.SECRET_KEY)
    private_key = ks.entries['gateway-identity']
    private_key.decrypt(config.SECRET_KEY)
    public_key = crypto.load_certificate(crypto.FILETYPE_ASN1, private_key.cert_chain[0][1]).get_pubkey()
    return pem_publickey(public_key).decode()

def _get_jwt_username(token):
    jks_secret = open_jks(jks_file)

    log.info("Secret is %s"%(jks_secret))
    contents = jwt.decode(token, jks_secret)
    username = contents['sub']
    log.info("Username %s"%(username))
    return username

def _find_user_from_ldap(username, sm):
    """extracted from flask_appbuilder.security.manager.BaseSecurityManager.auth_user_ldap(self, username, password)"""
    user = sm.find_user(username)
    if not user and config.AUTH_USER_REGISTRATION:
        con = ldap.initialize(config.AUTH_LDAP_SERVER)
        con.set_option(ldap.OPT_REFERRALS, 0)
        # TODO: Missing management of AUTH_LDAP_USE_TLS
        indirect_user = config.AUTH_LDAP_BIND_USER
        if indirect_user:
            indirect_password = config.AUTH_LDAP_BIND_PASSWORD
            log.debug("LDAP indirect bind with: {0}".format(indirect_user))
            con.bind_s(indirect_user, indirect_password)
            log.debug("LDAP BIND indirect OK")
        new_user = sm._search_ldap(ldap, con, username)
        if not new_user:
            log.info("Username %s"%username)
            return None
        ldap_user_info = new_user[0][1]
        if sm.auth_user_registration and user is None:
            user = sm.add_user(
                username=username,
                first_name=sm.ldap_extract(ldap_user_info, sm.auth_ldap_firstname_field, username),
                last_name=sm.ldap_extract(ldap_user_info, sm.auth_ldap_lastname_field, username),
                email=sm.ldap_extract(ldap_user_info, sm.auth_ldap_email_field, username + '@email.notfound'),
                role=sm.find_role(sm.auth_user_registration_role)
            )
    return user

def parse_hadoop_jwt():
    auth_service = "/gateway/"
    login_url = auth_service + "knoxsso/knoxauth/login.html?originalUrl=" + auth_service + "sandbox/superset"
    logout_url = auth_service + "knoxssout/api/v1/webssout"
    
    log.info("Request URL: %s"%request.url)
    log.info("Headers: %s"%dict(request.headers))

    if g.user is not None and g.user.is_authenticated:
        log.info("Already authenticated: %s"%g.user)
        return None

    jwt_token = request.cookies.get("hadoop-jwt", None)
    log.debug("Token: %s"%jwt_token)
    if not jwt_token:
        log.info("Failed parsing token")
        return redirect(login_url)
    username = _get_jwt_username(jwt_token)
    log.debug("Username %s"%username)
    user = _find_user_from_ldap(username, security_manager)
    if not user:
        log.info("Authentication failed for user: %s"%user)
        return redirect(login_url)
    login_user(user, remember=False)
    return None

