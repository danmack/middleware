from middlewared.api.base import BaseModel


class VendorNameArgs(BaseModel):
    pass


class VendorNameResult(BaseModel):
    result: str | None


class UnvendorArgs(BaseModel):
    pass


class UnvendorResult(BaseModel):
    result: None
