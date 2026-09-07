import uuid

from pydantic import BaseModel

from app.schemas.common import ORMModel


class IntegrationOut(ORMModel):
    id: uuid.UUID
    name: str
    type: str
    config_ref: str
    enabled: bool


class IntegrationIn(BaseModel):
    name: str
    type: str
    config_ref: str
    enabled: bool = True
