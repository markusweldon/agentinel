"""Classifier precision guards: false-positive / false-negative regressions + annotation axes."""

from __future__ import annotations

from agentinel.mcp_client import ServerSnapshot
from agentinel.models import ToolInfo
from agentinel.scanner import analyze
from agentinel.static.classifier import classify_tool
from agentinel.taxonomy import AttackClass, Severity


def _axes(name: str, desc: str = "", annotations: dict | None = None):
    return classify_tool(ToolInfo(server="s", name=name, description=desc, annotations=annotations))


def test_write_tool_with_content_noun_is_not_untrusted_input():
    # create_issue mentions "issue" and a read verb ("view"), but it is a writer — NOT axis A.
    assert not _axes(
        "create_issue", "Create a new issue. Returns the created issue so you can view its number."
    ).untrusted_input
    # A genuine reader of the same content IS axis A.
    assert _axes("issue_read", "Read an issue by number").untrusted_input


def test_camelcase_acronym_is_split_for_matching():
    # getAPIKey must normalize to "get api key" so the "api key" sensitive term matches.
    assert _axes("getAPIKey", "").sensitive_access


def test_overbroad_customer_term_no_longer_trips_sensitive_access():
    # A plain CRM update is a writer (C), not sensitive-access (B) — "customer" alone no longer trips B.
    axes = _axes("update_customer", "Update a customer record")
    assert axes.external_comms and not axes.sensitive_access


def test_ordinary_support_server_is_not_a_high_trifecta():
    tools = [
        ToolInfo(server="help", name="list_tickets", description="List tickets and read customer comments"),
        ToolInfo(server="help", name="reply_ticket", description="Post a reply to a customer ticket"),
    ]
    findings = analyze([ServerSnapshot(server_name="help", tools=tools)]).findings
    tri = [f for f in findings if f.attack_class is AttackClass.LETHAL_TRIFECTA]
    assert all(f.severity is not Severity.HIGH for f in tri), "ordinary support server should not be a HIGH trifecta"


def test_annotations_only_raise_never_clear():
    # Annotations can *raise* risk from the annotation alone...
    assert _axes("do_thing", "Does a thing", annotations={"readOnlyHint": False}).external_comms
    assert _axes("do_thing", "Does a thing", annotations={"openWorldHint": True}).untrusted_input
    assert _axes("do_thing", "Does a thing", annotations={"destructiveHint": True}).external_comms
    # ...but a self-declared readOnlyHint=true must NOT clear a keyword-derived capability.
    assert _axes("delete_record", "Delete the record", annotations={"readOnlyHint": True}).external_comms
