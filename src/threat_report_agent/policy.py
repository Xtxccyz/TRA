from __future__ import annotations

import hashlib
import json
from importlib import resources
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from threat_report_agent.contracts import ActionProposal


class PolicyModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PresetResourceLimits(PolicyModel):
    max_files: int = Field(ge=1)
    max_total_bytes: int = Field(ge=1)
    max_archive_depth: int = Field(ge=0)
    max_cpu_seconds_per_tool: int = Field(ge=1)
    max_memory_mb_per_tool: int = Field(ge=64)


class PresetCommand(PolicyModel):
    id: str
    version: str
    task_type: Literal[
        "SINGLE_SAMPLE_STATIC_DEEP",
        "FILE_SET_AND_CARRIER",
        "INCIDENT_REPORT_GENERATION",
    ]
    object_scope: tuple[str, ...]
    expected_outputs: tuple[str, ...]
    default_breadth: Literal["B0", "B1", "B2", "B3", "B4"]
    default_depth: Literal["D0", "D1", "D2", "D3", "D4", "D5"]
    resource_limits: PresetResourceLimits
    completion_conditions: tuple[str, ...]
    analysis_modules: tuple[str, ...]
    tool_names: tuple[str, ...]


class ToolPolicy(PolicyModel):
    name: str
    allowed_modules: tuple[str, ...]
    max_cpu_seconds: int
    max_memory_mb: int
    sample_execution: bool
    network_access: bool


class PolicyDecision(PolicyModel):
    allowed: bool
    reason: str
    policy_version: str


class PolicyRegistry:
    def __init__(
        self,
        presets: tuple[PresetCommand, ...],
        tools: tuple[ToolPolicy, ...],
        *,
        catalog_digest: str,
        policy_version: str,
    ) -> None:
        self._preset_catalog = presets
        self._presets = {item.id: item for item in presets}
        self._tools = {item.name: item for item in tools}
        self.catalog_digest = catalog_digest
        self.policy_version = policy_version

    @classmethod
    def load_builtin(cls) -> "PolicyRegistry":
        package = resources.files("threat_report_agent")
        catalog_bytes = package.joinpath("policies/preset-commands.json").read_bytes()
        tool_bytes = package.joinpath("policies/tool-policy.json").read_bytes()
        catalog = json.loads(catalog_bytes)
        tool_policy = json.loads(tool_bytes)
        return cls(
            tuple(PresetCommand.model_validate(item) for item in catalog["presets"]),
            tuple(ToolPolicy.model_validate(item) for item in tool_policy["tools"]),
            catalog_digest=hashlib.sha256(catalog_bytes).hexdigest(),
            policy_version=tool_policy["version"],
        )

    def require_preset(self, preset_id: str) -> PresetCommand:
        try:
            return self._presets[preset_id]
        except KeyError as exc:
            raise ValueError(f"Unknown preset command: {preset_id}") from exc

    def list_presets(self) -> tuple[PresetCommand, ...]:
        return self._preset_catalog

    def require_tool(self, tool_name: str) -> ToolPolicy:
        try:
            return self._tools[tool_name]
        except KeyError as exc:
            raise ValueError(f"Unknown tool policy: {tool_name}") from exc

    def authorize(self, proposal: ActionProposal) -> PolicyDecision:
        policy = self._tools.get(proposal.tool_name)
        if policy is None:
            return PolicyDecision(
                allowed=False,
                reason="TOOL_NOT_WHITELISTED",
                policy_version=self.policy_version,
            )
        if proposal.requires_sample_execution or not policy.sample_execution:
            if proposal.requires_sample_execution:
                return PolicyDecision(
                    allowed=False,
                    reason="SAMPLE_EXECUTION_DENIED",
                    policy_version=self.policy_version,
                )
        if proposal.requires_network or not policy.network_access:
            if proposal.requires_network:
                return PolicyDecision(
                    allowed=False,
                    reason="NETWORK_ACCESS_DENIED",
                    policy_version=self.policy_version,
                )
        if proposal.cpu_seconds > policy.max_cpu_seconds:
            return PolicyDecision(
                allowed=False,
                reason="CPU_LIMIT_EXCEEDED",
                policy_version=self.policy_version,
            )
        if proposal.memory_mb > policy.max_memory_mb:
            return PolicyDecision(
                allowed=False,
                reason="MEMORY_LIMIT_EXCEEDED",
                policy_version=self.policy_version,
            )
        return PolicyDecision(
            allowed=True,
            reason="AUTHORIZED",
            policy_version=self.policy_version,
        )
