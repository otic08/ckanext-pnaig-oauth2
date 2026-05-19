# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid
# Copyright (c) 2018 Future Internet Consulting and Development Solutions S.L.

# This file is part of PNAIG OAuth2 CKAN Extension.

# PNAIG OAuth2 CKAN Extension is free software: you can redistribute it and/or
# modify it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the License,
# or (at your option) any later version.

# PNAIG OAuth2 CKAN Extension is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with PNAIG OAuth2 CKAN Extension.
# If not, see <http://www.gnu.org/licenses/>.

import logging
from .oauth2 import *
import os
import jwt

from functools import partial
from flask_login import current_user, login_user, logout_user
from ckan import plugins
from ckan.common import g
from ckan.plugins import toolkit
import ckan.model as model
import ckanext.pnaig_oauth2.db as db
import urllib.parse
from ckanext.pnaig_oauth2.views import get_blueprints
from ckanext.pnaig_oauth2.cli import get_commands

log = logging.getLogger(__name__)


def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@toolkit.auth_sysadmins_check
def user_create(context, data_dict):
    msg = toolkit._('Users cannot be created.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_update(context, data_dict):
    msg = toolkit._('Users cannot be edited.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


class _PnaigOauth2Plugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IClick)

    # IBlueprint

    def get_blueprint(self):
        return get_blueprints()

    # IClick

    def get_commands(self):
        return get_commands()


class PnaigOauth2Plugin(_PnaigOauth2Plugin, plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IAuthFunctions, inherit=True)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IMiddleware, inherit=True)

    _request_loader_installed = False
    _request_loader_attempted = False

    # IMiddleware

    def make_middleware(self, app, config):
        # Exempt CKAN API blueprint from CSRF so Bearer token API calls work.
        # CKAN 2.11 enables Flask-WTF CSRFProtect globally but does not exempt
        # its own API endpoints, causing 400 on POST/PUT/DELETE with Bearer auth.
        # This runs after all blueprints are registered.
        try:
            from ckan.config.middleware.flask_app import csrf
            from ckan.views.api import api as api_blueprint
            csrf.exempt(api_blueprint)
            log.debug('Exempted CKAN API blueprint from CSRF protection')
        except (ImportError, AttributeError) as e:
            log.debug('Could not exempt API blueprint from CSRF: %s', e)
        return app

    def __init__(self, name=None):
        '''Store the OAuth 2 client configuration'''
        log.debug('Init PNAIG OAuth2 extension')
        self.name = name or 'pnaig_oauth2'
        self.oauth2helper = None

    def get_helpers(self):
        return {
            'pnaig_oauth2_get_stored_token': self.get_stored_token_helper,
            'pnaig_oauth2_refresh_token': self.oauth2helper.refresh_token,
        }

    def get_stored_token_helper(self, user_name=None):
        """Template helper to get stored OAuth2 token for a user"""
        if not user_name:
            user_name = getattr(toolkit.g, 'user', None)

        if not user_name:
            return None

        try:
            return self.oauth2helper.get_stored_token(user_name)
        except Exception as e:
            log.error(f"Error getting stored token for user {user_name}: {e}")
            return None

    def _install_request_loader(self):
        """Override Flask-Login's request_loader to handle OAuth2 Bearer/X-Tapis-Token.

        Must be called lazily (at first request time) because login_manager is
        created after make_middleware() runs in CKAN 2.11.3's flask_app.py.
        """
        from flask import current_app

        try:
            from ckan.views import _get_user_for_apitoken
        except ImportError as ie:
            log.error(
                'Cannot import _get_user_for_apitoken from ckan.views -- '
                'request_loader will NOT be installed. CKAN native API '
                'token fallback will be unavailable. ImportError: %s', ie
            )
            raise

        login_manager = current_app.login_manager
        plugin_ref = self  # closure reference

        @login_manager.request_loader
        def pnaig_oauth2_load_user_from_request(request):
            """Flask-Login request_loader: validate Bearer/X-Tapis-Token, fall back to CKAN API tokens."""
            g.login_via_auth_header = True

            apikey = request.headers.get(plugin_ref.authorization_header, '')
            if not apikey:
                apikey = request.headers.get('X-Tapis-Token', '')

            if apikey:
                if apikey.startswith('Bearer '):
                    apikey = apikey[7:].strip()
                try:
                    token = {'access_token': apikey}
                    user_name, user_obj = plugin_ref.oauth2helper.identify(token)
                    if user_obj is None and user_name:
                        user_obj = model.User.by_name(user_name)
                    if user_obj is not None:
                        return user_obj
                except Exception as e:
                    log.debug('request_loader: OAuth2 identify failed: %s', e)

            return _get_user_for_apitoken()

        log.info('Registered PNAIG OAuth2 request_loader on Flask-Login login_manager')

    def identify(self):
        log.debug('Starting identify process')

        if not self._request_loader_installed and not self._request_loader_attempted:
            self._request_loader_attempted = True
            try:
                self._install_request_loader()
                self._request_loader_installed = True
            except Exception as e:
                log.error('Failed to install PNAIG OAuth2 request_loader: %s', e)

        def _refresh_and_save_token(user_name):
            log.debug(f'Refreshing token for user {user_name}')
            try:
                new_token = self.oauth2helper.refresh_token(user_name)
            except Exception as e:
                log.error(f'Token refresh failed for user {user_name}: {e}')
                new_token = None

            if new_token:
                toolkit.g.usertoken = new_token
                log.debug(f'Token refreshed for user {user_name}')
            else:
                log.warning(f'Token refresh unsuccessful for user {user_name}, logging out')
                toolkit.g.user = None
                toolkit.g.userobj = None
                toolkit.g.usertoken = None
                g.user = None
                logout_user()

        def _check_and_refresh_stored_token(user_name):
            """Check if stored token is expired and refresh if needed.

            Returns True if the user should be logged out (refresh failed).
            """
            if toolkit.g.usertoken and toolkit.g.usertoken.get('access_token') and self.oauth2helper.jwt_enable:
                is_expired, _ = self.oauth2helper.check_token_expiration(
                    toolkit.g.usertoken['access_token']
                )
                if is_expired:
                    log.info('Stored token expired for user %s, attempting refresh', user_name)
                    new_token = self.oauth2helper.refresh_token(user_name)
                    if new_token:
                        toolkit.g.usertoken = new_token
                        log.info('Stored token refreshed for user %s', user_name)
                    else:
                        log.warning('Stored token refresh failed for user %s, logging out', user_name)
                        toolkit.g.user = None
                        toolkit.g.userobj = None
                        toolkit.g.usertoken = None
                        g.user = None
                        logout_user()
                        return True
            return False

        tapis_header_used = False
        apikey = toolkit.request.headers.get(self.authorization_header, '')

        if not apikey:
            tapis_token = toolkit.request.headers.get('X-Tapis-Token', '')
            if tapis_token:
                apikey = tapis_token
                tapis_header_used = True

        if not apikey and current_user.is_authenticated:
            user_name = current_user.name
            g.user = user_name
            toolkit.g.user = user_name
            toolkit.g.userobj = model.User.by_name(user_name)
            toolkit.g.usertoken = self.oauth2helper.get_stored_token(user_name)
            toolkit.g.usertoken_refresh = partial(_refresh_and_save_token, user_name)

            login_user(toolkit.g.userobj)

            if _check_and_refresh_stored_token(user_name):
                return
            return

        user_name = None
        user_obj = None

        if apikey:

            if apikey.startswith('Bearer '):
                apikey = apikey[7:].strip()
            try:
                token = {'access_token': apikey}
                user_name, user_obj = self.oauth2helper.identify(token)
                log.debug(f'Auth success: {user_name}')
            except jwt.ExpiredSignatureError:
                log.info('JWT token expired for API request, attempting refresh')
                try:
                    claims = self.oauth2helper._decode_jwt(apikey, verify=False)
                    expired_username = claims.get(self.oauth2helper.jwt_username_field)
                    if expired_username:
                        new_token = self.oauth2helper.refresh_token(expired_username)
                        if new_token:
                            user_name = expired_username
                            log.info('Token refreshed for user %s', expired_username)
                        else:
                            log.warning('Token refresh failed for user %s', expired_username)
                    else:
                        log.warning('Could not extract username from expired token')
                except Exception as e:
                    log.error('Error during token refresh: %s', e)
            except Exception as e:
                log.warning('Auth error for %s token: %s: %s',
                            'X-Tapis-Token' if tapis_header_used else 'Bearer',
                            type(e).__name__, e)

        if tapis_header_used and user_name is None:
            toolkit.abort(401, 'Invalid or expired X-Tapis-Token')

        if user_name is None and current_user.is_authenticated:
            user_name = current_user.name
            log.info('User %s logged using session' % user_name)

        if user_name:
            g.user = user_name
            toolkit.g.user = user_name
            toolkit.g.userobj = user_obj if user_obj else model.User.by_name(user_name)
            toolkit.g.usertoken = self.oauth2helper.get_stored_token(user_name)

            login_user(toolkit.g.userobj)

            if not apikey:
                _check_and_refresh_stored_token(user_name)

            toolkit.g.usertoken_refresh = partial(_refresh_and_save_token, user_name)
        else:
            g.user = None
            toolkit.g.user = None
            toolkit.g.userobj = None
            log.warning('The user is not currently logged...')

    def get_auth_functions(self):
        return {
            'user_update': user_update,
            'user_reset': user_reset,
            'request_reset': request_reset
        }

    def update_config(self, config):
        log.debug('update config...')
        log.debug(f'Config values - site_url: {config.get("ckan.site_url")}, root_path: {config.get("ckan.root_path")}')

        self.oauth2helper = OAuth2Helper(config)
        log.debug(f'OAuth2Helper initialized - redirect_uri: {self.oauth2helper.redirect_uri}')

        db.init_db()

        self.register_url = os.environ.get("CKAN_OAUTH2_REGISTER_URL", config.get('ckan.oauth2.register_url', None))
        self.reset_url = os.environ.get("CKAN_OAUTH2_RESET_URL", config.get('ckan.oauth2.reset_url', None))
        self.edit_url = os.environ.get("CKAN_OAUTH2_EDIT_URL", config.get('ckan.oauth2.edit_url', None))
        self.authorization_header = os.environ.get("CKAN_OAUTH2_AUTHORIZATION_HEADER", config.get('ckan.oauth2.authorization_header', 'Authorization')).lower()

        plugins.toolkit.add_template_directory(config, 'templates')
