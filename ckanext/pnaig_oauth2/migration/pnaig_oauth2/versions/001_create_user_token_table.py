"""create user_token table

Revision ID: 001_create_user_token_table
Revises:
Create Date: 2025-10-18

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '001_create_user_token_table'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    engine = op.get_bind()
    inspector = sa.inspect(engine)
    tables = inspector.get_table_names()

    if "user_token" not in tables:
        op.create_table(
            'user_token',
            sa.Column('user_name', sa.UnicodeText, primary_key=True),
            sa.Column('access_token', sa.UnicodeText),
            sa.Column('token_type', sa.UnicodeText),
            sa.Column('refresh_token', sa.UnicodeText),
            sa.Column('expires_in', sa.UnicodeText),
        )


def downgrade():
    op.drop_table('user_token')
