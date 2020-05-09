"""initializing

Revision ID: dc06f8767847
Revises: 
Create Date: 2020-04-28 13:07:25.854295

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dc06f8767847'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'auth_types',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True, nullable=False),
        sa.Column('name', sa.String(10), nullable=False),
    )

    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column('full_name', sa.String(15), nullable=False),
        sa.Column('email', sa.String(200), nullable=False, unique=True),
        sa.Column('password', sa.String(300), nullable=False),
        sa.Column('auth_type_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.Column('is_deleted', sa.Boolean(), default=False),
        sa.ForeignKeyConstraint(('auth_type_id',), ['auth_types.id']),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'boards',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column('uploader', sa.Integer(), nullable=False),
        sa.Column('modifier', sa.Integer(), nullable=True),
        sa.Column('name', sa.String(20), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.Column('is_deleted', sa.Boolean(), default=False),
        sa.ForeignKeyConstraint(('uploader',), ['users.id']),
        sa.ForeignKeyConstraint(('modifier',), ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'articles',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column('board_id', sa.Integer(), nullable=False),
        sa.Column('uploader', sa.Integer(), nullable=False),
        sa.Column('modifier', sa.Integer(), nullable=True),
        sa.Column('title', sa.String(50), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.Column('is_deleted', sa.Boolean(), default=False),
        sa.ForeignKeyConstraint(('board_id',), ['boards.id']),
        sa.ForeignKeyConstraint(('uploader',), ['users.id']),
        sa.ForeignKeyConstraint(('modifier',), ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'random_keys',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True, nullable=False),
        sa.Column('key', sa.String(50), nullable=False),
    )


def downgrade():
    pass
