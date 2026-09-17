from am64x_secure_toolkit.services.claim_boundary import claims_for
from am64x_secure_toolkit.services.secret_policy import contains_unredacted_secret_field, sanitize_for_record
from am64x_secure_toolkit.workflow import WorkflowResult


def test_workflow_result_serializes():
    result = WorkflowResult(status="PASS", operation="x", summary="ok", checks=[{"check":"a","status":"PASS"}])
    assert result.to_dict()["status"] == "PASS"


def test_claim_boundary_never_turns_host_pass_into_hardware_pass():
    claims, non_claims = claims_for("application_build", "PASS", encrypted=True)
    assert claims
    joined = " ".join(non_claims)
    assert "Hardware application-authentication" in joined
    assert "Customer Root of Trust" in joined
    assert "HS-FS -> HS-SE" in joined


def test_secret_policy_redacts_named_fields():
    source = {"private_key": "/secret/key.pem", "nested": {"passphrase": "abc", "public_hash": "123"}}
    safe = sanitize_for_record(source)
    assert safe["private_key"] == "<REDACTED>"
    assert safe["nested"]["passphrase"] == "<REDACTED>"
    assert safe["nested"]["public_hash"] == "123"
    assert contains_unredacted_secret_field(source)
    assert not contains_unredacted_secret_field(safe)
