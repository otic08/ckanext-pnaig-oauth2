# -*- coding: utf-8 -*-

import logging
from flask import Blueprint, jsonify, make_response, redirect
import logging
from ckanext.pnaig_oauth2 import constants
from ckanext.pnaig_oauth2.oauth2 import get_came_from
from ckan.common import session
import ckan.lib.helpers as helpers
import ckan.plugins.toolkit as toolkit
import urllib.parse
import ckan.plugins as plugins
import ckan.model as model

log = logging.getLogger(__name__)
# service_proxy = Blueprint("service_proxy", __name__)
oauth2 = Blueprint("pnaig_oauth2", __name__)

def _get_oauth2helper():
    """Get OAuth2Helper from the loaded plugin"""
    plugin = plugins.get_plugin('pnaig_oauth2')
    return plugin.oauth2helper

def _get_previous_page(default_page):
    if 'came_from' not in toolkit.request.args:
        came_from_url = toolkit.request.headers.get('Referer', default_page)
    else:
        came_from_url = toolkit.request.args.get('came_from', default_page)

    came_from_url_parsed = urllib.parse.urlparse(came_from_url)

    # Ensure HTTPS scheme if the request is secure
    if toolkit.request.environ.get('HTTPS') == 'on' or toolkit.request.scheme == 'https':
        came_from_url = urllib.parse.urlunparse(
            ('https',) + came_from_url_parsed[1:]
        )
        came_from_url_parsed = urllib.parse.urlparse(came_from_url)

    # Avoid redirecting users to external hosts
    if came_from_url_parsed.netloc != '' and came_from_url_parsed.netloc != toolkit.request.host:
        came_from_url = default_page

    # When a user is being logged and REFERER == HOME or LOGOUT_PAGE
    # he/she must be redirected to the dashboard
    pages = ['/', '/user/logged_out_redirect']
    if came_from_url_parsed.path in pages:
        came_from_url = default_page

    return came_from_url

@oauth2.route('/user/login')
def login():
    log.debug('login')
    came_from_url = _get_previous_page(constants.INITIAL_PAGE)
    return _get_oauth2helper().challenge(came_from_url)

@oauth2.route('/oauth2/callback')
def callback():
    try:
        oauth2helper = _get_oauth2helper()
        token = oauth2helper.get_token()
        # log.debug(f'token:{token}')
        user_name,user_obj = oauth2helper.identify(token)
        oauth2helper.log_user_into_ckan(user_obj)
        oauth2helper.update_token(user_name, token)
        response = oauth2helper.redirect_from_callback()
    except Exception as e:
        model.Session.rollback()

        # If the callback is called with an error, we must show the message
        error_description = toolkit.request.args.get('error_description')
        if not error_description:
            if str(e):
                error_description = str(e)
            elif hasattr(e, 'description') and e.description:
                error_description = e.description
            elif hasattr(e, 'error') and e.error:
                error_description = e.error
            else:
                error_description = type(e).__name__
        log.error(f'login error: {error_description}')
        redirect_url = get_came_from(toolkit.request.args.get('state'))
        redirect_url = '/' if redirect_url == constants.INITIAL_PAGE else redirect_url
        response = redirect(redirect_url)
        helpers.flash_error(error_description)

    return response

def get_blueprints():
    return [oauth2]
