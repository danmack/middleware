"""Failover master node

Revision ID: 74cf6ec20dcd
Revises: d38e9cc6174c
Create Date: 2019-10-07 08:39:20.884714+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '74cf6ec20dcd'
down_revision = 'd38e9cc6174c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('system_failover', schema=None) as batch_op:
        batch_op.add_column(sa.Column('master_node', sa.String(length=1), nullable=True))

    op.execute("UPDATE system_failover SET master_node = 'A'")

    with op.batch_alter_table('system_failover', schema=None) as batch_op:
        batch_op.alter_column('master_node',
               existing_type=sa.VARCHAR(length=1),
               nullable=False)
        batch_op.drop_column('master')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('system_failover', schema=None) as batch_op:
        batch_op.add_column(sa.Column('master', sa.BOOLEAN(), nullable=False))
        batch_op.drop_column('master_node')

    # ### end Alembic commands ###
