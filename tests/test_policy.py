import pytest

from attestor.errors import PolicyError
from attestor.models import Severity
from attestor.policy import list_packs, load_policy, pack_text, policy_from_dict


def test_default_policy_is_finance():
    policy = load_policy()
    assert policy.pack == "finance"
    assert policy.config_for("prohibited_language").options["terms"]
    assert any("FINRA" in ref for ref in policy.config_for("citation_grounding").regulatory_refs)


def test_general_pack_turns_off_finance_wording_rules():
    policy = policy_from_dict({"pack": "general"})
    assert not policy.config_for("required_disclosures").enabled
    assert not policy.config_for("prohibited_language").enabled
    assert policy.config_for("pii_leak").enabled


def test_user_overrides_merge_over_pack(tmp_path):
    path = tmp_path / "attestor.yaml"
    path.write_text("pack: finance\nchecks:\n  citation_grounding:\n    support_threshold: 0.8\n")
    cfg = load_policy(path).config_for("citation_grounding")
    assert cfg.options["support_threshold"] == 0.8
    assert cfg.options["reject_threshold"] == 0.3
    assert cfg.severity is Severity.BLOCK


def test_unknown_check_rejected():
    with pytest.raises(PolicyError, match="unknown check"):
        policy_from_dict({"checks": {"nope": {}}})


def test_unknown_pack_rejected():
    with pytest.raises(PolicyError, match="unknown pack"):
        pack_text("banking")


def test_invalid_yaml(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("checks: [\n")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_policy_hash_is_stable():
    assert load_policy().sha256() == load_policy().sha256()
    assert load_policy().sha256() != policy_from_dict({"pack": "general"}).sha256()


def test_list_packs():
    packs = list_packs()
    assert {"finance", "general"} <= set(packs)
    assert packs["finance"]
