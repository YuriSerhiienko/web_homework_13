"""username to email

Revision ID: 1c4204572f7a
Revises: 
Create Date: 2023-09-23 16:01:39.508507

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "1c4204572f7a"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column("users", sa.Column("email", sa.String(), nullable=True))
    op.drop_index("ix_users_username", table_name="users")
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.drop_column("users", "username")
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column(
        "users", sa.Column("username", sa.VARCHAR(), autoincrement=False, nullable=True)
    )
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.create_index("ix_users_username", "users", ["username"], unique=False)
    op.drop_column("users", "email")
    # ### end Alembic commands ###
