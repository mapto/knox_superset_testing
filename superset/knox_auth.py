import base64
import jwt
import jks
from OpenSSL import crypto
from OpenSSL._util import lib as cryptolib
 
from flask import g, redirect, request, flash
from flask_login import login_user
from flask_appbuilder import expose
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.views import AuthLDAPView

from superset import security_manager
from superset.security import SupersetSecurityManager
from superset.config import SECRET_KEY as master_secret

import logging
log = logging.getLogger(__name__)

jks_file = "/etc/ssl/keystores/gateway.jks"
jwt_key = "hadoop-jwt="

# master_secret = 'knox'
"""
class NoAuthView(AuthLDAPView):
    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)

        username = request.args.get("user.name")
        log.info("Username %s"%username)
        user = self.appbuilder.sm.find_user(username)
        if not user:
            flash(as_unicode(self.invalid_login_message), 'warning')
            return redirect(self.appbuilder.get_url_for_login)
        login_user(user, remember=True)
        return redirect(self.appbuilder.get_url_for_index)

class NoSecurityManager(SupersetSecurityManager):
    # authdbview = AuthJWTView
    authldapview = NoAuthView


class BasicAuthView(AuthLDAPView):
    def _get_basic_credentials(self, auth_header):
        if auth_header[:6] != "Basic ":
            return None
        credentials = str(base64.b64decode(auth_header[6:])).split(":")
        log.info("Credentials %s:%s"%(credentials[0],credentials[1]))
        return credentials[0], credentials[1]

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)

        u,p = self._get_basic_credentials(request.headers["Authorization"])
        user = self.appbuilder.sm.auth_user_ldap(u, p)
        if not user:
            flash(as_unicode(self.invalid_login_message), 'warning')
            return redirect(self.appbuilder.get_url_for_login)
        login_user(user, remember=True)
        return redirect(self.appbuilder.get_url_for_index)

class BasicAuthSecurityManager(SupersetSecurityManager):
    # authdbview = AuthJWTView
    authldapview = BasicAuthView
"""

def pem_publickey(pkey):
    """ Format a public key as a PEM. From https://stackoverflow.com/a/30929459/1827854"""
    bio = crypto._new_mem_buf()
    cryptolib.PEM_write_bio_PUBKEY(bio, pkey._pkey)
    return crypto._bio_to_string(bio)

def open_jks(jks_file, master_secret):
    ks = jks.KeyStore.load(jks_file, master_secret)
    private_key = ks.entries['gateway-identity']
    private_key.decrypt(master_secret)
    public_key = crypto.load_certificate(crypto.FILETYPE_ASN1, private_key.cert_chain[0][1]).get_pubkey()
    return pem_publickey(public_key).decode()

def _get_jwt_username(token):
    secret_key = open_jks(jks_file, master_secret)

    log.info("Secret is %s"%(secret_key))
    contents = jwt.decode(token, secret_key)
    username = contents['sub']
    log.info("Username %s"%(username))
    return username

def _get_jwt_token(cookie_header):
    if not cookie_header:
        return None
    for c in cookie_header.split(";"):
        cookie = c.strip()
        if cookie.startswith(jwt_key):
            jwt_token = cookie.strip()[len(jwt_key):]
            return jwt_token
    return None

def parse_hadoop_jwt():
    auth_url = "https://172.17.0.1:8443/gateway/knoxsso/knoxauth/login.html?originalUrl=https://172.17.0.1:8443/gateway/sandbox/dummy"
    
    # print("JWT login")
    log.info("JWT login")
    # logging.info("JWT login")
    if g.user is not None and g.user.is_authenticated:
        # print("Already authenticated: %s"%g.user)
        log.info("Already authenticated: %s"%g.user)
        return None

    log.info("Request URL: %s"%request.url)
    log.info("Headers: %s"%dict(request.headers))
    """
    print("Cookies: %s"%request.headers["Cookie"])
    log.info("Cookies: %s"%request.headers["Cookie"])
    jwt_token = self._get_jwt_token(request.headers["Cookie"])
    """
    jwt_token = _get_jwt_token(request.headers.get("Cookie"))
    # print("Token: %s"%jwt_token)
    log.info("Token: %s"%jwt_token)
    if not jwt_token:
        log.info("Failed parsing token")
        return redirect(auth_url)
    username = _get_jwt_username(jwt_token)
    log.info("Username %s"%username)
    # user = security_manager.find_user(username)
    # import ipdb; ipdb.set_trace()
    user = security_manager.find_user("admin")
    if not user:
        log.info("Authentication failed for user: %s"%user)
        return redirect(auth_url)
    login_user(user, remember=True)
    return None

class AuthJWTView(AuthLDAPView):
    """
    def __init__(self):
        print("AuthJWTView")
        log.info("AuthJWTView")
        logging.info("AuthJWTView")
        super.__init__()
    """


    '''
    def parse_jwt(self):
        """to be used with flask's @app.before_request"""

        if g.user is not None and g.user.is_authenticated:
            log.info("Already authenticated: %s"%g.user)
            return None

        log.info("Cookies: %s"%request.headers["Cookie"])
        jwt_token = self._get_jwt_token(request.headers["Cookie"])
        log.info("Token: %s"%jwt_token)
        if not jwt_token:
            log.info("Failed parsing token")
            return "Failed"
        username = self._get_jwt_username(jwt_token)
        log.info("Username %s"%username)
        user = self.appbuilder.sm.find_user(username)
        if not user:
            log.info("Authentication failed: %s"%user)
            return "Failed"
        login_user(user, remember=True)
        return None
    '''

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        # print("JWT login")
        log.info("JWT login")
        # logging.info("JWT login")
        if g.user is not None and g.user.is_authenticated:
            # print("Already authenticated: %s"%g.user)
            log.info("Already authenticated: %s"%g.user)
            return super().login()

        log.info("Request URL: %s"%request.url)
        log.info("Headers: %s"%dict(request.headers))
        """
        print("Cookies: %s"%request.headers["Cookie"])
        log.info("Cookies: %s"%request.headers["Cookie"])
        jwt_token = self._get_jwt_token(request.headers["Cookie"])
        """
        jwt_token = _get_jwt_token(request.headers.get("Cookie"))
        # print("Token: %s"%jwt_token)
        log.info("Token: %s"%jwt_token)
        if not jwt_token:
            log.info("Failed parsing token")
            flash(as_unicode(self.invalid_login_message), 'warning')
            return super().login()
        username = _get_jwt_username(jwt_token)
        log.info("Username %s"%username)
        user = self.appbuilder.sm.find_user(username)
        if not user:
            log.info("Authentication failed: %s"%user)
            flash(as_unicode(self.invalid_login_message), 'warning')
            return super().login()
        login_user(user, remember=True)
        return super().login()

class JwtSecurityManager(SupersetSecurityManager):
    authldapview = AuthJWTView

    """
    def __init__(self):
        print("Set JWT security manager")
        log.info("Set JWT security manager")
        logging.info("Set JWT security manager")
        # authdbview = AuthJWTView
        authldapview = AuthJWTView
        super.__init()
    """