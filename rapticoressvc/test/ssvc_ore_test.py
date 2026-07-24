"""Deterministic decision-tree (golden) tests for ssvc_recommendations.

These pin the SSVC policy end-to-end without any network or NVD format
dependency: NVD lookups, KEV status, and EPSS are mocked, so each case is a
known-answer test of the four-vector decision logic. Cases include the payload
shapes glass-comb-api sends and the Bug B / Bug D regressions.
"""
from rapticoressvc import ssvc_ore
from rapticoressvc import ssvc_recommendations
from rapticoressvc import vector_calculator_helpers
from rapticoressvc.nvd_data_helper import normalize_nvd_2_cve
from rapticoressvc.test.testing_helper import make_nvd_2_cve

# A network-attack, no-user-interaction CVSS v3.1 vector (AV:N, UI:N).
VECTOR_NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def _record(cve, vector=VECTOR_NET, score=10.0):
    return normalize_nvd_2_cve(make_nvd_2_cve(cve, vector=vector, score=score))


def _patch(mocker, nvd_records=None, kev_cves=()):
    nvd_records = nvd_records or {}
    mocker.patch.object(ssvc_ore, 'get_nvd_data',
                        side_effect=lambda cves, *a, **k: {c: nvd_records.get(c) for c in
                                                           (cves if isinstance(cves, list) else [cves])})
    mocker.patch.object(ssvc_ore, 'get_epss_scores_batch', return_value={})
    mocker.patch.object(vector_calculator_helpers, 'check_cve_kevc_status',
                        side_effect=lambda cve: cve in kev_cves)


def test_kev_critical_public_prod_compute_is_act_now(mocker):
    cve = "CVE-2021-44228"
    _patch(mocker, nvd_records={cve: _record(cve, score=10.0)}, kev_cves={cve})
    r = ssvc_recommendations("compute_asset", [cve], "public", "production", "compute", "critical")
    assert r["ssvc_rec"] == "act_now"


def test_no_exploit_critical_public_prod_compute_is_schedule(mocker):
    cve = "CVE-2024-0001"
    _patch(mocker, nvd_records={cve: _record(cve, score=10.0)}, kev_cves=set())
    r = ssvc_recommendations("compute_asset", [cve], "public", "production", "compute", "critical")
    assert r["ssvc_rec"] == "schedule"


def test_bug_b_production_db_low_does_not_crash(mocker):
    # glass-comb sends lowercased criticality; production/db/low must resolve, not crash.
    cve = "CVE-2021-44228"
    _patch(mocker, nvd_records={cve: _record(cve, score=10.0)}, kev_cves={cve})
    r = ssvc_recommendations("db_asset", [cve], "private", "production", "db", "low")
    assert r["ssvc_rec"] == "schedule"


def test_bug_d_severity_only_defers_and_has_no_epss(mocker):
    # Severity-only input (no CVE) must not fabricate per-character "CVEs" for EPSS.
    _patch(mocker, nvd_records={}, kev_cves=set())
    r = ssvc_recommendations("None_asset", "medium", "None", "non_production", "None", "low")
    assert r["ssvc_rec"] == "defer"
    assert r["epss_score"] is None
    assert r["cve"] == "medium"


def test_multi_cve_uses_highest_score(mocker):
    low, high = "CVE-2019-1111", "CVE-2021-44228"
    _patch(mocker, nvd_records={low: _record(low, score=4.0), high: _record(high, score=10.0)},
           kev_cves={high})
    r = ssvc_recommendations("compute_asset", [low, high], "public", "production", "compute", "critical")
    assert r["vulnerability_score"] == 10.0
    assert r["ssvc_rec"] == "act_now"


def test_unknown_cve_falls_back_to_review(mocker):
    cve = "CVE-1900-0000"
    _patch(mocker, nvd_records={cve: None}, kev_cves=set())
    r = ssvc_recommendations("compute_asset", [cve], "public", "production", "compute", "high")
    assert r["ssvc_rec"] == "review"
