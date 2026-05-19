# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid

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

import sqlalchemy as sa
from sqlalchemy import Table, Column, types, orm
import logging
from ckan.model import meta, domain_object

log = logging.getLogger(__name__)

# Define the user_token table
user_token_table = Table(
    'user_token',
    meta.metadata,
    Column('user_name', types.UnicodeText, primary_key=True),
    Column('access_token', types.UnicodeText),
    Column('token_type', types.UnicodeText),
    Column('refresh_token', types.UnicodeText),
    Column('expires_in', types.UnicodeText),
    extend_existing=True
)


class UserToken(domain_object.DomainObject):
    """Model for storing OAuth2 tokens for users"""

    @classmethod
    def by_user_name(cls, user_name):
        """Get user token by username"""
        return meta.Session.query(cls).filter_by(user_name=user_name).first()


# Map the class to the table using SQLAlchemy 1.4+ API
_mapper_registry = orm.registry()
_mapper_registry.map_imperatively(UserToken, user_token_table)


def init_db():
    """
    Initialize the database tables.
    Note: Table creation is handled by Alembic migrations.
    Run: ckan db upgrade -p pnaig_oauth2

    This function ensures the ORM mapping is set up.
    """
    # The table and mapping are already defined above
    # This function is kept for backward compatibility
    log.debug('PNAIG OAuth2 database models initialized')
