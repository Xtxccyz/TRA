"""Bounded lifecycle for long-running analysis turns.

The DSH conversation must not hold one model turn open while a static task is
running. This control-plane state machine models the hand-off: the requesting
turn starts analysis, returns an asynchronous wait state, and a later
event-driven turn performs synthesis. It has no sample or tool authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


TurnState = Literal[
    "IDLE",
    "ANALYSIS_RUNNING",
    "AWAITING_EVENT",
    "SYNTHESIZING",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
]
TERMINAL_STATES = frozenset({"COMPLETED", "FAILED", "CANCELLED"})


@dataclass(frozen=True)
class TurnLifecycleSnapshot:
    state: TurnState
    turn_id: str | None
    parent_turn_id: str | None
    last_event_seq: int


class LongTurnLifecycle:
    """Enforce asynchronous analysis and terminal-only conversation branching."""

    def __init__(self) -> None:
        self._state: TurnState = "IDLE"
        self._turn_id: str | None = None
        self._parent_turn_id: str | None = None
        self._last_event_seq = 0

    @property
    def snapshot(self) -> TurnLifecycleSnapshot:
        return TurnLifecycleSnapshot(
            self._state, self._turn_id, self._parent_turn_id, self._last_event_seq
        )

    def start_analysis(self, turn_id: str) -> TurnLifecycleSnapshot:
        if self._state not in {"IDLE", *TERMINAL_STATES}:
            raise RuntimeError("TURN_ALREADY_ACTIVE")
        if not str(turn_id).strip():
            raise ValueError("turn_id is required")
        self._turn_id = str(turn_id)
        self._parent_turn_id = None
        self._last_event_seq = 0
        self._state = "ANALYSIS_RUNNING"
        return self.snapshot

    def return_async(self) -> TurnLifecycleSnapshot:
        if self._state != "ANALYSIS_RUNNING":
            raise RuntimeError("ANALYSIS_NOT_RUNNING")
        self._state = "AWAITING_EVENT"
        return self.snapshot

    def accept_event(self, sequence: int, *, terminal: bool = False) -> TurnLifecycleSnapshot:
        if self._state != "AWAITING_EVENT":
            raise RuntimeError("TURN_NOT_WAITING")
        if not isinstance(sequence, int) or sequence <= self._last_event_seq:
            raise ValueError("EVENT_SEQUENCE_MUST_ADVANCE")
        self._last_event_seq = sequence
        if terminal:
            self._state = "SYNTHESIZING"
        return self.snapshot

    def begin_synthesis(self) -> TurnLifecycleSnapshot:
        if self._state != "SYNTHESIZING":
            raise RuntimeError("SYNTHESIS_NOT_READY")
        return self.snapshot

    def complete(self) -> TurnLifecycleSnapshot:
        if self._state != "SYNTHESIZING":
            raise RuntimeError("TURN_NOT_SYNTHESIZING")
        self._state = "COMPLETED"
        return self.snapshot

    def fail(self) -> TurnLifecycleSnapshot:
        if self._state not in {"ANALYSIS_RUNNING", "AWAITING_EVENT", "SYNTHESIZING"}:
            raise RuntimeError("TURN_NOT_ACTIVE")
        self._state = "FAILED"
        return self.snapshot

    def cancel(self) -> TurnLifecycleSnapshot:
        if self._state not in {"ANALYSIS_RUNNING", "AWAITING_EVENT", "SYNTHESIZING"}:
            raise RuntimeError("TURN_NOT_ACTIVE")
        self._state = "CANCELLED"
        return self.snapshot

    def branch(self, turn_id: str) -> TurnLifecycleSnapshot:
        """Create a new conversation turn only from a terminal turn."""
        if self._state not in TERMINAL_STATES:
            raise RuntimeError("BRANCH_REQUIRES_TERMINAL_TURN")
        if not str(turn_id).strip():
            raise ValueError("turn_id is required")
        self._parent_turn_id = self._turn_id
        self._turn_id = str(turn_id)
        self._state = "IDLE"
        return self.snapshot
