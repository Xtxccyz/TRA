from threat_report_agent.investigation import MechanismPlaybookRegistry


def test_round10_registry_contains_all_production_playbook_types() -> None:
    types = {item.mechanism_type for item in MechanismPlaybookRegistry.default_playbooks()}
    assert {
        "DECODE_CONFIG", "DYNAMIC_API_RESOLUTION", "PPID_SPOOFING", "ENTRY_TIMELINE",
        "HTTP_DOWNLOAD", "PROCESS_EXECUTION", "DEFENDER_MODIFICATION", "ETW_PATCH",
        "SCHEDULED_TASK_EXECUTION", "PLUGIN_MODULE_LOAD",
    } <= types
    assert all(item.question_templates and item.verifier_contract for item in MechanismPlaybookRegistry.default_playbooks() if item.version.startswith("2."))
