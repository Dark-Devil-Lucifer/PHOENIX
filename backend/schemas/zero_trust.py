from pydantic import BaseModel, Field


class ZeroTrustPolicyCreate(BaseModel):
    policy_uid: str = Field(min_length=2, max_length=100)
    name: str = Field(min_length=2, max_length=255)

    description: str | None = None

    source_segment: str | None = None
    destination_segment: str | None = None

    action: str = "deny"

    required_role: str | None = None
    required_device_state: str | None = None


class ZeroTrustEvaluateRequest(BaseModel):
    decision_uid: str = Field(min_length=2, max_length=100)

    source_segment: str
    destination_segment: str

    user_id: int | None = None
    asset_id: int | None = None

    user_roles: list[str] = []
    device_state: str | None = None
