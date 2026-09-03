from threat_report_agent.agents import StaticAnalysisAgent, TriageAgent
from threat_report_agent.prompts import PromptRegistry
from threat_report_agent.static_analysis import StaticFact


def test_triage_agent_assigns_document_role_with_versioned_prompt_metadata() -> None:
    agent = TriageAgent(PromptRegistry.load_builtin(), model_route="deterministic")

    decision = agent.triage("invoice.pdf", "pdf", is_container=False)

    assert decision.role == "DOCUMENT"
    assert decision.obligation == "REQUIRED"
    assert decision.metadata["prompt_id"] == "triage-agent"
    assert len(decision.metadata["prompt_sha256"]) == 64


def test_static_agent_derives_supported_behavior_claims_from_static_facts() -> None:
    agent = StaticAnalysisAgent(PromptRegistry.load_builtin(), model_route="deterministic")
    facts = (
        StaticFact(
            "decryption",
            "crypto_indicator",
            {"indicator": "CryptDecrypt"},
            {"type": "file_offset", "offset": 10},
        ),
        StaticFact(
            "loader",
            "loader_indicator",
            {"indicator": "VirtualAlloc"},
            {"type": "file_offset", "offset": 20},
        ),
        StaticFact(
            "c2_network",
            "network_indicator",
            {"indicator": "https://evil.example/x"},
            {"type": "file_offset", "offset": 30},
        ),
        StaticFact(
            "anti_analysis",
            "anti_analysis_indicator",
            {"indicator": "IsDebuggerPresent"},
            {"type": "file_offset", "offset": 40},
        ),
    )

    claims = agent.propose_claims(facts, "payload.bin")

    assert {claim.module for claim in claims} == {
        "decryption",
        "loader",
        "c2_network",
        "anti_analysis",
    }
    assert all(claim.subject == "payload.bin" for claim in claims)
    assert all(
        claim.fact_indexes
        and all(0 <= fact_index < len(facts) for fact_index in claim.fact_indexes)
        for claim in claims
    )


def test_static_agent_does_not_infer_behavior_from_unrelated_facts() -> None:
    agent = StaticAnalysisAgent(PromptRegistry.load_builtin(), model_route="deterministic")
    facts = (
        StaticFact(
            "static_triage",
            "string",
            {"text": "ordinary text", "encoding": "ascii"},
            {"type": "file_offset", "offset": 0},
        ),
    )

    assert agent.propose_claims(facts, "document.txt") == ()
