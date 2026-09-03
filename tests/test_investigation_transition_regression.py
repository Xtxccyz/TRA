from threat_report_agent.investigation import (
    InvestigationLoopDriver,
    InvestigationThreadState,
)


def test_initial_gate_enters_investigating_before_verifying() -> None:
    result = InvestigationLoopDriver(max_steps=4).run(
        thread_id='thread',
        artifact_id='artifact',
        question='What mechanism is present?',
        hypothesis_id='hypothesis',
        hypothesis_statement='The artifact has a static mechanism.',
        initial_evidence=(
            {'id': 'e1', 'kind': 'function', 'nature': 'STATIC_OBSERVED', 'value': {}},
            {'id': 'e2', 'kind': 'function_call', 'nature': 'STATIC_OBSERVED', 'value': {}},
        ),
        proposed_actions=(),
        allow_investigator_actions=False,
    )

    assert result.thread_state is InvestigationThreadState.CLAIM_READY
    states = [event.state for event in result.events if event.phase == 'state']
    assert 'INVESTIGATING' in states
    assert states.index('INVESTIGATING') < states.index('VERIFYING')
