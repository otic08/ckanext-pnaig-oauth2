# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid
# Copyright (c) 2018 Future Internet Consulting and Development Solutions S.L.

# This file is part of OAuth2 CKAN Extension.

# OAuth2 CKAN Extension is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# OAuth2 CKAN Extension is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with OAuth2 CKAN Extension.  If not, see <http://www.gnu.org/licenses/>.


from base64 import b64encode, b64decode, urlsafe_b64encode
from typing import Optional
import json
import logging
import os
import jwt
import requests
from urllib.parse import urljoin
from oauthlib.oauth2 import InsecureTransportError
from requests_oauthlib import OAuth2Session
from ckan.plugins import toolkit # type: ignore
from ckan.common import session, login_user
import ckan.model as model
import ckanext.pnaig_oauth2.db as db
from .constants import *

log = logging.getLogger(__name__)


def generate_state(url):
    return b64encode(bytes(json.dumps({CAME_FROM_FIELD: url}).encode()))


def get_came_from(state):
    return json.loads(b64decode(state)).get(CAME_FROM_FIELD, '/')


REQUIRED_CONF = ("authorization_endpoint", "token_endpoint", "client_id", "client_secret", "profile_api_url", "profile_api_user_field", "profile_api_mail_field")

class OAuth2Helper(object):

    def __init__(self, config):
        # Config is required - should be passed from plugin's update_config()
        cfg = config

        self.verify_https = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT', '') == ""
        if self.verify_https and os.environ.get("REQUESTS_CA_BUNDLE", "").strip() != "":
            self.verify_https = os.environ["REQUESTS_CA_BUNDLE"].strip()

        self.jwt_enable = str(os.environ.get('CKAN_OAUTH2_JWT_ENABLE', cfg.get('ckan.oauth2.jwt.enable',''))).strip().lower() in ("true", "1", "on")
        self.jwt_algorithm = str(os.environ.get('CKAN_OAUTH2_JWT_ALGORITHM', cfg.get('ckan.oauth2.jwt.algorithm', 'HS256'))).strip()
        self.jwt_secret = str(os.environ.get('CKAN_OAUTH2_JWT_SECRET', cfg.get('ckan.oauth2.jwt.secret', ''))).strip()
        # Replace literal \n with actual newlines for PEM format
        jwt_public_key_raw = str(os.environ.get('CKAN_OAUTH2_JWT_PUBLIC_KEY', cfg.get('ckan.oauth2.jwt.public_key', ''))).strip()
        self.jwt_public_key = jwt_public_key_raw.replace('\\n', '\n') if jwt_public_key_raw else ''
        if self.jwt_public_key:
            log.debug('JWT public key loaded')

        # JWT token field names - configurable for different OAuth2 providers
        self.jwt_username_field = str(os.environ.get('CKAN_PNAIG_OAUTH2_JWT_USERNAME_FIELD', cfg.get('ckanext.pnaig_oauth2.jwt.username_field', 'username'))).strip()
        self.jwt_email_field = str(os.environ.get('CKAN_PNAIG_OAUTH2_JWT_EMAIL_FIELD', cfg.get('ckanext.pnaig_oauth2.jwt.email_field', 'email'))).strip()
        self.jwt_fullname_field = str(os.environ.get('CKAN_PNAIG_OAUTH2_JWT_FULLNAME_FIELD', cfg.get('ckanext.pnaig_oauth2.jwt.fullname_field', 'name'))).strip()
        self.jwt_firstname_field = str(os.environ.get('CKAN_PNAIG_OAUTH2_JWT_FIRSTNAME_FIELD', cfg.get('ckanext.pnaig_oauth2.jwt.firstname_field', 'given_name'))).strip()
        self.jwt_lastname_field = str(os.environ.get('CKAN_PNAIG_OAUTH2_JWT_LASTNAME_FIELD', cfg.get('ckanext.pnaig_oauth2.jwt.lastname_field', 'family_name'))).strip()

        self.legacy_idm = str(os.environ.get('CKAN_PNAIG_OAUTH2_LEGACY_IDM', cfg.get('ckanext.pnaig_oauth2.legacy_idm', ''))).strip().lower() in ("true", "1", "on")
        self.authorization_endpoint = str(os.environ.get('CKAN_PNAIG_OAUTH2_AUTHORIZATION_ENDPOINT', cfg.get('ckanext.pnaig_oauth2.authorization_endpoint', ''))).strip()
        self.token_endpoint = str(os.environ.get('CKAN_PNAIG_OAUTH2_TOKEN_ENDPOINT', cfg.get('ckanext.pnaig_oauth2.token_endpoint', ''))).strip()
        self.profile_api_url = str(os.environ.get('CKAN_PNAIG_OAUTH2_PROFILE_API_URL', cfg.get('ckanext.pnaig_oauth2.profile_api_url', ''))).strip()
        self.client_id = str(os.environ.get('CKAN_PNAIG_OAUTH2_CLIENT_ID', cfg.get('ckanext.pnaig_oauth2.client_id', ''))).strip()
        self.client_secret = str(os.environ.get('CKAN_PNAIG_OAUTH2_CLIENT_SECRET', cfg.get('ckanext.pnaig_oauth2.client_secret', ''))).strip()
        self.scope = str(os.environ.get('CKAN_PNAIG_OAUTH2_SCOPE', cfg.get('ckanext.pnaig_oauth2.scope', ''))).strip()
        self.profile_api_user_field = str(os.environ.get('CKAN_PNAIG_OAUTH2_PROFILE_API_USER_FIELD', cfg.get('ckanext.pnaig_oauth2.profile_api_user_field', ''))).strip()
        self.profile_api_fullname_field = str(os.environ.get('CKAN_PNAIG_OAUTH2_PROFILE_API_FULLNAME_FIELD', cfg.get('ckanext.pnaig_oauth2.profile_api_fullname_field', ''))).strip()
        self.profile_api_firstname_field = str(os.environ.get('CKAN_PNAIG_OAUTH2_PROFILE_API_FIRSTNAME_FIELD', cfg.get('ckanext.pnaig_oauth2.profile_api_firstname_field', ''))).strip()
        self.profile_api_lastname_field = str(os.environ.get('CKAN_PNAIG_OAUTH2_PROFILE_API_LASTNAME_FIELD', cfg.get('ckanext.pnaig_oauth2.profile_api_lastname_field', ''))).strip()
        self.profile_api_mail_field = str(os.environ.get('CKAN_PNAIG_OAUTH2_PROFILE_API_MAIL_FIELD', cfg.get('ckanext.pnaig_oauth2.profile_api_mail_field', ''))).strip()
        self.profile_api_groupmembership_field = str(os.environ.get('CKAN_PNAIG_OAUTH2_PROFILE_API_GROUPMEMBERSHIP_FIELD', cfg.get('ckanext.pnaig_oauth2.profile_api_groupmembership_field', ''))).strip()
        self.sysadmin_group_name = str(os.environ.get('CKAN_PNAIG_OAUTH2_SYSADMIN_GROUP_NAME', cfg.get('ckanext.pnaig_oauth2.sysadmin_group_name', ''))).strip()
        self.token_response_path = str(os.environ.get('CKAN_PNAIG_OAUTH2_TOKEN_RESPONSE_PATH', cfg.get('ckanext.pnaig_oauth2.token_response_path', ''))).strip()
        self.token_response_key = str(os.environ.get('CKAN_PNAIG_OAUTH2_TOKEN_RESPONSE_KEY', cfg.get('ckanext.pnaig_oauth2.token_response_key', 'access_token'))).strip()
        self.profile_response_path = str(os.environ.get('CKAN_PNAIG_OAUTH2_PROFILE_RESPONSE_PATH', cfg.get('ckanext.pnaig_oauth2.profile_response_path', ''))).strip()

        site_url = cfg.get('ckan.site_url', 'http://localhost:5000')
        root_path = cfg.get('ckan.root_path')
        log.debug(f'OAuth2Helper.__init__: site_url={site_url}, root_path={root_path}')
        self.redirect_uri = urljoin(urljoin(site_url, root_path), REDIRECT_URL)
        log.debug(f'OAuth2Helper.__init__: redirect_uri={self.redirect_uri}')

        log.info('OAuth2 endpoint config: profile_api_url=%s, authorization_endpoint=%s, token_endpoint=%s',
                 self.profile_api_url, self.authorization_endpoint, self.token_endpoint)
        log.info('OAuth2 profile field config: user_field=%s, mail_field=%s, fullname_field=%s, firstname_field=%s, lastname_field=%s, groupmembership_field=%s',
                 self.profile_api_user_field, self.profile_api_mail_field, self.profile_api_fullname_field,
                 self.profile_api_firstname_field, self.profile_api_lastname_field, self.profile_api_groupmembership_field)
        if self.jwt_enable:
            log.info('OAuth2 JWT field config: username_field=%s, email_field=%s, fullname_field=%s, firstname_field=%s, lastname_field=%s',
                     self.jwt_username_field, self.jwt_email_field, self.jwt_fullname_field,
                     self.jwt_firstname_field, self.jwt_lastname_field)

        missing = [key for key in REQUIRED_CONF if getattr(self, key, "") == ""]
        if missing:
            raise ValueError("Missing required oauth2 conf: %s" % ", ".join(missing))
        elif self.scope == "":
            self.scope = None

    def _unwrap_response(self, data, path):
        """Unwrap a nested API response by following a dot-separated path.

        If path is empty/None, returns data unchanged.
        """
        if not path:
            return data
        for key in path.split('.'):
            if isinstance(data, dict) and key in data:
                data = data[key]
            else:
                log.warning('_unwrap_response: key "%s" not found (path: %s)', key, path)
                return data
        return data

    def _compliance_fix(self, session):
        """Apply compliance hooks to the OAuth2 session."""
        def _fix_access_token(response):
            if not self.token_response_path:
                return response
            data = response.json()
            # Step 1: Navigate to the container using token_response_path (e.g. "result")
            unwrapped = self._unwrap_response(data, self.token_response_path)
            # Step 2: Extract the full token payload dict from token_response_key
            # (e.g. "access_token" -> the dict containing access_token, token_type, etc.)
            if self.token_response_key and self.token_response_key in unwrapped:
                response._content = json.dumps(unwrapped[self.token_response_key]).encode('utf-8')
            return response

        session.register_compliance_hook('access_token_response', _fix_access_token)
        return session

    def get_authorization_url(self, came_from_url):
        '''Return the OAuth2 authorization URL without redirecting.'''
        state = generate_state(came_from_url)
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=self.scope, state=state)
        oauth = self._compliance_fix(oauth)
        auth_url, _ = oauth.authorization_url(self.authorization_endpoint)
        log.debug('get_authorization_url: {0}'.format(auth_url))
        return auth_url

    def challenge(self, came_from_url):
        auth_url = self.get_authorization_url(came_from_url)
        log.debug('Challenge: Redirecting challenge to page {0}'.format(auth_url))
        # CKAN 2.6 only supports bytes
        return toolkit.redirect_to(auth_url)#.encode('utf-8'))

    def get_token(self):
        log.debug(f'get_token: OAUTHLIB_INSECURE_TRANSPORT={os.environ.get("OAUTHLIB_INSECURE_TRANSPORT", "not set")}')
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=self.scope)
        oauth = self._compliance_fix(oauth)  # Apply compliance fixes

        # Just because of FIWARE Authentication
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        if self.legacy_idm:
            # This is only required for Keyrock v6 and v5
            headers['Authorization'] = 'Basic %s' % urlsafe_b64encode(
                (f'{self.client_id}:{self.client_secret}').encode()
            )

        try:
            authorization_response = toolkit.request.url
            log.debug('get_token: fetching token from endpoint')
            token = oauth.fetch_token(self.token_endpoint,
                                      client_id=self.client_id,
                                      client_secret=self.client_secret,
                                      authorization_response=authorization_response,
                                      include_client_id=True)
            log.debug(f'get_token: token received successfully')
        except requests.exceptions.SSLError as e:
            # TODO search a better way to detect invalid certificates
            if "verify failed" in str(e):
                raise InsecureTransportError()
            else:
                raise
        except Exception as e:
            log.debug(f'error: {e}')
            raise
        return token

    def query_profile_api_legacy(self, token):
        try:
            profile_response = requests.get(self.profile_api_url + '?access_token=%s' % token['access_token'], verify=self.verify_https)
            if not profile_response.ok:
                raise ValueError(profile_response.json().get('error_description'))
            return profile_response
        except Exception as e:
            log.error(f'error: {e}')
            raise

    def query_profile_api_default(self, token):
        try:
            headers = {
                'Authorization': f"Bearer {token['access_token']}"
            }
            profile_response = requests.get(self.profile_api_url, headers=headers, verify=self.verify_https)
            if not profile_response.ok:
                raise ValueError(profile_response.json().get('error_description'))
            return profile_response
        except Exception as e:
            log.error(f'error: {e}')
            raise

    def find_user(self, username: Optional[str], email: Optional[str]) -> Optional[model.User]:
        if username:
            users = model.User.by_name(username)
            if users is not None and not isinstance(users, list):
                return users
            elif isinstance(users, list) and len(users) == 1:
                return users[0]
        if email:
            users = model.User.by_email(email)
            if users is not None and not isinstance(users, list):
                return users
            elif isinstance(users, list) and len(users) == 1:
                return users[0]
        raise ValueError("User not found")

    def create_user_object(self, user_profile) -> model.User:
        log.debug('create_user_object: incoming user_profile keys=%s', list(user_profile.keys()))
        email = user_profile.get(self.profile_api_mail_field) if self.profile_api_mail_field else None
        username = user_profile.get(self.profile_api_user_field) if self.profile_api_user_field else None
        log.debug('create_user_object: extracted username=%s, email=%s', username, email)
        if not username and not email:
            raise ValueError("Username or email is required but was not provided by OAuth provider")
        user = model.User(name=username, email=email)
        if self.profile_api_fullname_field and self.profile_api_fullname_field in user_profile:
            user.fullname = user_profile[self.profile_api_fullname_field]
            log.debug('create_user_object: fullname from fullname_field=%s', user.fullname)
        elif self.profile_api_firstname_field and self.profile_api_lastname_field and self.profile_api_firstname_field in user_profile and self.profile_api_lastname_field in user_profile:
            user.fullname = f"{user_profile[self.profile_api_firstname_field]} {user_profile[self.profile_api_lastname_field]}"
            log.debug('create_user_object: fullname from first+last=%s', user.fullname)
        elif self.profile_api_firstname_field and self.profile_api_firstname_field in user_profile:
            user.fullname = user_profile[self.profile_api_firstname_field]
            log.debug('create_user_object: fullname from firstname_field only=%s', user.fullname)
        elif self.profile_api_lastname_field and self.profile_api_lastname_field in user_profile:
            user.fullname = user_profile[self.profile_api_lastname_field]
            log.debug('create_user_object: fullname from lastname_field only=%s', user.fullname)
        else:
            log.debug('create_user_object: no fullname fields matched in profile')
        if self.profile_api_groupmembership_field and self.profile_api_groupmembership_field in user_profile:
            user.sysadmin = self.sysadmin_group_name in user_profile[self.profile_api_groupmembership_field]
            log.debug('create_user_object: sysadmin=%s (group_field=%s)', user.sysadmin, self.profile_api_groupmembership_field)
        log.debug('create_user_object: final user name=%s, email=%s, fullname=%s', user.name, user.email, user.fullname)
        return user

    def get_profile_from_jwt(self, access_token):
        """Extract user profile from JWT token claims.

        Returns a dict with profile fields mapped to the internal profile_api_* field names.
        """
        # Check if we have the appropriate key for verification
        has_key = (self.jwt_algorithm.startswith('HS') and self.jwt_secret) or \
                 (self.jwt_algorithm.startswith(('RS', 'ES')) and self.jwt_public_key)
        if not has_key:
            raise ValueError("JWT secret or public key not configured for algorithm %s" % self.jwt_algorithm)

        token_decoded = self._decode_jwt(access_token, verify=True)
        log.debug('get_profile_from_jwt: decoded token claims keys=%s', list(token_decoded.keys()))
        user_profile = {}

        # Extract username
        if self.jwt_username_field and self.jwt_username_field in token_decoded:
            user_profile[self.profile_api_user_field] = token_decoded[self.jwt_username_field]
            log.debug('get_profile_from_jwt: extracted username=%s from jwt field=%s', user_profile[self.profile_api_user_field], self.jwt_username_field)
        else:
            log.debug('get_profile_from_jwt: jwt_username_field=%s not found in token claims', self.jwt_username_field)

        # Extract email
        if self.jwt_email_field and self.jwt_email_field in token_decoded:
            user_profile[self.profile_api_mail_field] = token_decoded[self.jwt_email_field]
            log.debug('get_profile_from_jwt: extracted email=%s from jwt field=%s', user_profile[self.profile_api_mail_field], self.jwt_email_field)
        else:
            log.debug('get_profile_from_jwt: jwt_email_field=%s not found in token claims', self.jwt_email_field)

        # Extract fullname
        if self.jwt_fullname_field and self.jwt_fullname_field in token_decoded:
            user_profile[self.profile_api_fullname_field] = token_decoded[self.jwt_fullname_field]
            log.debug('get_profile_from_jwt: extracted fullname=%s from jwt field=%s', user_profile[self.profile_api_fullname_field], self.jwt_fullname_field)
        else:
            log.debug('get_profile_from_jwt: jwt_fullname_field=%s not found in token claims', self.jwt_fullname_field)

        # Extract firstname
        if self.jwt_firstname_field and self.jwt_firstname_field in token_decoded:
            user_profile[self.profile_api_firstname_field] = token_decoded[self.jwt_firstname_field]
            log.debug('get_profile_from_jwt: extracted firstname=%s from jwt field=%s', user_profile[self.profile_api_firstname_field], self.jwt_firstname_field)
        else:
            log.debug('get_profile_from_jwt: jwt_firstname_field=%s not found in token claims', self.jwt_firstname_field)

        # Extract lastname
        if self.jwt_lastname_field and self.jwt_lastname_field in token_decoded:
            user_profile[self.profile_api_lastname_field] = token_decoded[self.jwt_lastname_field]
            log.debug('get_profile_from_jwt: extracted lastname=%s from jwt field=%s', user_profile[self.profile_api_lastname_field], self.jwt_lastname_field)
        else:
            log.debug('get_profile_from_jwt: jwt_lastname_field=%s not found in token claims', self.jwt_lastname_field)

        log.debug('get_profile_from_jwt: final profile=%s', user_profile)
        return user_profile

    def get_profile_from_api(self, token):
        """Fetch user profile from the OAuth2 provider's profile/userinfo API.

        Returns the profile response as a dict.
        """
        profile_response = self.query_profile_api_legacy(token) if self.legacy_idm else self.query_profile_api_default(token)
        profile_data = profile_response.json()
        return self._unwrap_response(profile_data, self.profile_response_path)

    def identify(self, token):
        # Get profile from both JWT token and profile API, then merge
        user_profile = {}

        if self.jwt_enable:
            # Extract profile from JWT token
            access_token = token['access_token']
            jwt_profile = self.get_profile_from_jwt(access_token)
            user_profile.update(jwt_profile)

        # Fetch profile from API to get complementary information
        # API data will not override JWT data if both are present
        try:
            api_profile = self.get_profile_from_api(token)
            # Only add fields that are not already present from JWT
            for key, value in api_profile.items():
                if key not in user_profile:
                    user_profile[key] = value
        except Exception as e:
            # If profile API fails and we have JWT data, continue with JWT data only
            if not self.jwt_enable:
                raise
            log.warning(f"Failed to fetch profile from API: {e}. Continuing with JWT data only.")

        log.debug('identify: merged user_profile=%s', user_profile)

        # Try to find existing user
        try:
            user = self.find_user(
                user_profile.get(self.profile_api_user_field),
                user_profile.get(self.profile_api_mail_field)
            )
        except ValueError:
            # Create new user if not found
            user = self.create_user_object(user_profile)

        # Save the user in the database
        model.Session.add(user)
        model.Session.commit()
        model.Session.remove()
        return user.name, user

    def log_user_into_ckan(self, user_obj):
        # Log the user in and remember the session
        login_user(user_obj, remember=True)

    def redirect_from_callback(self):
        '''Redirect to the callback URL after a successful authentication.'''
        state = toolkit.request.args.get('state')
        came_from = get_came_from(state)
        log.debug(f'Redirect came_from: {came_from}')
        return toolkit.redirect_to(came_from)


    def get_stored_token(self, user_name):
        user_token = db.UserToken.by_user_name(user_name=user_name)
        if user_token:
            return {
                'access_token': user_token.access_token,
                'refresh_token': user_token.refresh_token,
                'expires_in': user_token.expires_in,
                'token_type': user_token.token_type if user_token.token_type else 'new_token_type'
            }
        else:
            return None

    def _decode_jwt(self, token, verify=True):
        """
        Decode JWT token using configured algorithm and secret/public key.
        """
        log.debug("_decode_jwt: verify=%s, algorithm=%s", verify, self.jwt_algorithm)
        try:
            if verify:
                # Determine the key to use based on algorithm
                if self.jwt_algorithm.startswith('HS'):
                    # Symmetric algorithms (HS256, HS384, HS512) use shared secret
                    if self.jwt_secret:
                        return jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm], verify=True)
                    else:
                        log.error('JWT secret not configured for symmetric algorithm %s, rejecting token', self.jwt_algorithm)
                        raise ValueError('JWT secret not configured for symmetric algorithm')
                elif self.jwt_algorithm.startswith('RS') or self.jwt_algorithm.startswith('ES'):
                    # Asymmetric algorithms (RS256, ES256, etc.) use public key
                    if self.jwt_public_key:
                        return jwt.decode(token, self.jwt_public_key, algorithms=[self.jwt_algorithm], verify=True)
                    else:
                        log.error('JWT public key not configured for asymmetric algorithm %s, rejecting token', self.jwt_algorithm)
                        raise ValueError('JWT public key not configured for asymmetric algorithm')
                else:
                    log.error('Unknown JWT algorithm %s, rejecting token', self.jwt_algorithm)
                    raise ValueError('Unknown JWT algorithm')
            else:
                return jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
        except jwt.ExpiredSignatureError:
            log.warning('JWT token expired (exp claim is in the past according to server clock)')
            raise
        except jwt.InvalidSignatureError as e:
            log.error('JWT signature verification failed (wrong public key or token tampered): %s', e)
            raise
        except (jwt.DecodeError, jwt.InvalidTokenError) as e:
            log.error('JWT decode error (%s): %s', type(e).__name__, e)
            raise

    def check_token_expiration(self, access_token):
        """Check if a JWT token is expired without raising.

        Returns:
            tuple: (is_expired: bool, username: str | None)
        """
        try:
            claims = self._decode_jwt(access_token, verify=True)
            username = claims.get(self.jwt_username_field)
            return False, username
        except jwt.ExpiredSignatureError:
            claims = self._decode_jwt(access_token, verify=False)
            username = claims.get(self.jwt_username_field)
            return True, username

    def update_token(self, user_name, token):
        try:
            user_token = db.UserToken.by_user_name(user_name=user_name)
        except AttributeError:
            user_token = None
        # Create the user if it does not exist
        if not user_token:
            user_token = db.UserToken()
            user_token.user_name = user_name
        # Save the new token
        user_token.access_token = token['access_token']
        user_token.token_type = 'new_token_type'
        user_token.refresh_token = token.get('refresh_token')
        if 'expires_in' in token:
            user_token.expires_in = token['expires_in']
        else:
            access_token = self._decode_jwt(user_token.access_token, verify=True)
            user_token.expires_in = access_token['exp'] - access_token['iat']

        model.Session.add(user_token)
        model.Session.commit()
        model.Session.remove()

    def refresh_token(self, user_name):
        token = self.get_stored_token(user_name)
        if token:
            client = OAuth2Session(self.client_id, token=token, scope=self.scope)
            client = self._compliance_fix(client)  # Apply compliance fixes
            try:
                token = client.refresh_token(self.token_endpoint, client_secret=self.client_secret, client_id=self.client_id, verify=self.verify_https)
            except requests.exceptions.SSLError as e:
                if "verify failed" in str(e):
                    raise InsecureTransportError()
                else:
                    raise
            except Exception as e:
                log.error('Failed to refresh token for user %s: %s' % (user_name, e))
                return None
            self.update_token(user_name, token)
            log.info('Token for user %s has been updated properly' % user_name)
            return token
        else:
            log.warning('User %s has no refresh token' % user_name)
            return None


