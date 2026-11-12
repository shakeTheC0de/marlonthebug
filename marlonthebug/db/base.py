"""Dependencies shared across database models."""

from datetime import datetime, timezone
from typing import Annotated

from sqlalchemy import Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

str256 = Annotated[str, mapped_column(Text(256))]
str1024 = Annotated[str, mapped_column(Text(1024))]
str8192 = Annotated[str, mapped_column(Text(8192))]

timestamp_now = Annotated[
    datetime,
    mapped_column(default=lambda: datetime.now(timezone.utc)),
]


class Base(DeclarativeBase):
    pass
