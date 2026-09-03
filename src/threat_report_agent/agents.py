from __future__ import annotations

from dataclasses import dataclass

from threat_report_agent.prompts import PromptRegistry
from threat_report_agent.static_analysis import ClaimSpec, StaticFact


@dataclass(frozen=True)
class TriageDecision:
    role: str
    obligation: str
    rationale: str
    metadata: dict[str, str]


@dataclass(frozen=True)
class FunctionEvidenceCandidate:
    artifact_id: str
    logical_path: str
    name: str
    entry: str
    xref_count: int
    cfg_block_count: int
    instruction_count: int
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class FunctionReviewClaim:
    subject: str
    object: str
    statement: str
    confidence: str
    evidence_ids: tuple[str, ...]


class _AgentBase:
    def __init__(self, prompts: PromptRegistry, prompt_id: str, model_route: str) -> None:
        self.prompt = prompts.require(prompt_id, "1.0.0")
        self.metadata = {
            "prompt_id": self.prompt.id,
            "prompt_version": self.prompt.version,
            "prompt_sha256": self.prompt.sha256,
            "model_route": model_route,
        }


class TriageAgent(_AgentBase):
    def __init__(self, prompts: PromptRegistry, model_route: str) -> None:
        super().__init__(prompts, "triage-agent", model_route)

    def triage(
        self, logical_path: str, detected_type: str, *, is_container: bool
    ) -> TriageDecision:
        if is_container:
            return TriageDecision(
                "CONTAINER", "SUPPORTING", "Container requires child coverage.", self.metadata
            )
        roles = {
            "pe": "EXECUTABLE",
            "script": "SCRIPT",
            "pdf": "DOCUMENT",
            "ooxml": "DOCUMENT",
            "ole": "DOCUMENT",
        }
        role = roles.get(detected_type, "UNKNOWN")
        return TriageDecision(
            role, "REQUIRED", f"Static format classification for {logical_path}.", self.metadata
        )


class StaticAnalysisAgent(_AgentBase):
    def __init__(self, prompts: PromptRegistry, model_route: str) -> None:
        super().__init__(prompts, "static-analysis-agent", model_route)

    def propose_claims(
        self,
        facts: tuple[StaticFact, ...],
        subject: str,
    ) -> tuple[ClaimSpec, ...]:
        indexes_by_kind: dict[str, list[int]] = {}
        for index, fact in enumerate(facts):
            indexes_by_kind.setdefault(fact.kind, []).append(index)

        crypto_indexes = indexes_by_kind.get("crypto_indicator", [])
        decryption_indexes = (
            crypto_indexes
            + indexes_by_kind.get("encoded_blob", [])
            + indexes_by_kind.get("high_entropy_section", [])
            + indexes_by_kind.get("mechanism_resource_payload", [])
            + indexes_by_kind.get("mechanism_decompression", [])
            + indexes_by_kind.get("mechanism_decompression_format", [])
            + indexes_by_kind.get("mechanism_decode", [])
            + indexes_by_kind.get("mechanism_integrity_check", [])
        )
        mechanism_decryption_indexes = (
            indexes_by_kind.get("mechanism_resource_payload", [])
            + indexes_by_kind.get("mechanism_decompression", [])
            + indexes_by_kind.get("mechanism_decompression_format", [])
            + indexes_by_kind.get("mechanism_decode", [])
            + indexes_by_kind.get("mechanism_integrity_check", [])
        )
        loader_indexes = (
            indexes_by_kind.get("loader_indicator", [])
            + indexes_by_kind.get("mechanism_resource_extraction", [])
            + indexes_by_kind.get("mechanism_memory_permission", [])
            + indexes_by_kind.get("mechanism_dynamic_resolution", [])
        )
        execution_indexes = (
            indexes_by_kind.get("execution_indicator", [])
            + indexes_by_kind.get("process_creation_flags", [])
        )
        network_indexes = (
            indexes_by_kind.get("network_indicator", [])
            + indexes_by_kind.get("script_indicator", [])
            + indexes_by_kind.get("document_url", [])
        )
        anti_indexes = (
            indexes_by_kind.get("anti_analysis_indicator", [])
            + indexes_by_kind.get("mechanism_environment_check", [])
            + indexes_by_kind.get("mechanism_service_query", [])
        )
        chain_indexes = indexes_by_kind.get("mechanism_chain", [])
        simulation_indexes = indexes_by_kind.get("abstract_execution_trace", [])

        claims: list[ClaimSpec] = []
        # Abstract execution is a deterministic static tool result.  Promote
        # only its explicit mechanism candidates to candidate Claims; the
        # trace itself remains Evidence and is never presented as runtime
        # observation.
        simulation_mapping = {
            "memory_loader": ("loader", "may_prepare_memory", "a secondary buffer", "T1055", "Process Injection"),
            "memory_execution": ("execution", "may_start_thread_from_memory", "a thread entry point", "T1055", "Process Injection"),
            "ppid_spoofing": ("execution", "may_spoof_parent_process", "parent process identity", "T1134.004", "Parent PID Spoofing"),
            "network_staging": ("c2_network", "may_stage_network_data", "a network endpoint and buffer", "T1071", "Application Layer Protocol"),
            "dynamic_loader": ("loader", "may_resolve_and_start_payload", "a dynamically resolved entry point", "T1129", "Shared Modules"),
        }
        for index in simulation_indexes:
            value = facts[index].value if isinstance(facts[index].value, dict) else {}
            candidates = value.get("mechanism_candidates", [])
            if not isinstance(candidates, list):
                continue
            for candidate in candidates[:8]:
                if not isinstance(candidate, dict):
                    continue
                kind = str(candidate.get("kind", ""))
                mapping = simulation_mapping.get(kind)
                if mapping is None:
                    continue
                module, action, obj, technique_id, technique_name = mapping
                sequence = " -> ".join(str(item) for item in candidate.get("api_sequence", []) if item)
                claims.append(
                    ClaimSpec(
                        module,
                        subject,
                        action,
                        obj,
                        sequence or kind,
                        "static abstract execution prediction; runtime execution is not observed",
                        (
                            f"{subject} has a static abstract execution path consistent with {kind}"
                            + (f" ({sequence})" if sequence else "")
                            + "; this is a bounded prediction requiring corroboration."
                        ),
                        (index,),
                        "HIGH" if str(value.get("confidence")) == "HIGH" else "MEDIUM",
                        {
                            "technique_id": technique_id,
                            "name": technique_name,
                            "status": "candidate",
                        },
                    )
                )
        if decryption_indexes:
            resource_details = [
                facts[index].value
                for index in indexes_by_kind.get("mechanism_resource_payload", [])
                if isinstance(facts[index].value, dict)
            ]
            decompression_details = [
                facts[index].value
                for index in indexes_by_kind.get("mechanism_decompression_format", [])
                if isinstance(facts[index].value, dict)
            ]
            decode_details = [
                facts[index].value
                for index in indexes_by_kind.get("mechanism_decode", [])
                if isinstance(facts[index].value, dict)
            ]
            detail_parts: list[str] = []
            if resource_details:
                detail_parts.append(
                    f"{resource_details[0].get('count', '?')} RT_RCDATA resources"
                )
            if decompression_details:
                detail_parts.append(
                    f"RtlDecompressBuffer format {decompression_details[0].get('compression_format', '?')} "
                    f"({decompression_details[0].get('format', 'decompression candidate')})"
                )
            if decode_details:
                constants = decode_details[0].get("algorithm_constants")
                if constants:
                    detail_parts.append(f"custom XOR state constants {', '.join(map(str, constants))}")
            detail_statement = "; ".join(detail_parts)
            claims.append(
                ClaimSpec(
                    "decryption",
                    subject,
                    "may_decode_or_decrypt",
                    "embedded resource or transient buffer",
                    (
                        "resource payload -> decompression -> byte transformation -> integrity check"
                        if mechanism_decryption_indexes
                        else "static crypto, encoding, or high-entropy indicators"
                    ),
                    "inferred from file content without execution",
                    (
                    f"{subject} contains a static resource/decompression/decode chain "
                        + (f"({detail_statement}) " if detail_statement else "")
                        + "consistent with staged payload processing."
                        if mechanism_decryption_indexes
                        else f"{subject} contains indicators consistent with decoding or decryption logic."
                    ),
                    tuple(decryption_indexes[:12]),
                    "HIGH" if len(mechanism_decryption_indexes) >= 2 else "MEDIUM" if crypto_indexes else "LOW",
                    {
                        "technique_id": "T1027",
                        "name": "Obfuscated/Compressed Files",
                        "status": "candidate",
                    },
                )
            )
        if loader_indexes:
            loader_details: list[str] = []
            for kind in (
                "mechanism_resource_extraction",
                "mechanism_dynamic_resolution",
                "mechanism_memory_permission",
            ):
                for index in indexes_by_kind.get(kind, []):
                    value = facts[index].value
                    if isinstance(value, dict):
                        if value.get("api"):
                            loader_details.append(str(value["api"]))
                        elif value.get("apis"):
                            loader_details.extend(str(item) for item in value["apis"])
            loader_detail = ", ".join(dict.fromkeys(loader_details))
            claims.append(
                ClaimSpec(
                    "loader",
                    subject,
                    "may_load_or_prepare_memory",
                    "code or a secondary component",
                    (
                        "resource extraction, dynamic API resolution, and memory permission changes"
                        if any(
                            indexes_by_kind.get(kind)
                            for kind in (
                                "mechanism_resource_extraction",
                                "mechanism_memory_permission",
                                "mechanism_dynamic_resolution",
                            )
                        )
                        else "loader and memory-management APIs"
                    ),
                    "inferred from static imports, strings, and function references",
                    (
                        f"{subject} contains a loader-like chain that extracts or resolves "
                        f"secondary data and prepares memory ({loader_detail}); execution is not proven."
                        if any(
                            indexes_by_kind.get(kind)
                            for kind in (
                                "mechanism_resource_extraction",
                                "mechanism_memory_permission",
                                "mechanism_dynamic_resolution",
                            )
                        )
                        else f"{subject} exposes APIs commonly used for loading or in-memory execution."
                    ),
                    tuple(loader_indexes[:12]),
                    "MEDIUM",
                    {
                        "technique_id": "T1129",
                        "name": "Shared Modules",
                        "status": "candidate",
                    },
                )
            )
        if execution_indexes:
            flag_details: list[str] = []
            for index in indexes_by_kind.get("process_creation_flags", []):
                value = facts[index].value
                if isinstance(value, dict):
                    for item in value.get("flags", []):
                        if isinstance(item, dict):
                            flag_details.append(
                                f"{item.get('value')}: {', '.join(str(flag) for flag in item.get('set_flags', []))}"
                            )
            claims.append(
                ClaimSpec(
                    "execution",
                    subject,
                    "may_execute",
                    "a process or command",
                    "process creation or command execution API",
                    "inferred from static imports or strings",
                    (
                        f"{subject} contains process-creation indicators"
                        f" ({'; '.join(flag_details[:4])}); runtime execution is not proven."
                        if flag_details
                        else f"{subject} contains indicators associated with process or command execution."
                    ),
                    tuple(execution_indexes[:12]),
                    "MEDIUM",
                    {
                        "technique_id": "T1059",
                        "name": "Command and Scripting Interpreter",
                        "status": "candidate",
                    },
                )
            )
        if network_indexes:
            claims.append(
                ClaimSpec(
                    "c2_network",
                    subject,
                    "references_network_endpoint",
                    "one or more network indicators",
                    "embedded URL, domain, or IP literal",
                    "endpoint purpose is not confirmed by static evidence alone",
                    f"{subject} contains network endpoints that require correlation before C2 attribution.",
                    tuple(network_indexes[:20]),
                    "MEDIUM",
                    {
                        "technique_id": "T1071",
                        "name": "Application Layer Protocol",
                        "status": "candidate",
                    },
                )
            )
        if anti_indexes:
            anti_details: list[str] = []
            for kind in ("mechanism_environment_check", "mechanism_service_query"):
                for index in indexes_by_kind.get(kind, []):
                    value = facts[index].value
                    if isinstance(value, dict):
                        if value.get("api"):
                            anti_details.append(str(value["api"]))
                        elif value.get("apis"):
                            anti_details.extend(str(item) for item in value["apis"])
            anti_detail = ", ".join(dict.fromkeys(anti_details))
            claims.append(
                ClaimSpec(
                    "anti_analysis",
                    subject,
                    "may_detect_analysis",
                    "system resources, memory layout, or service state",
                    (
                        "environment and service discovery API combination"
                        if any(
                            indexes_by_kind.get(kind)
                            for kind in ("mechanism_environment_check", "mechanism_service_query")
                        )
                        else "anti-analysis API or environment string"
                    ),
                    "inferred from static imports, strings, and function references",
                    (
                        f"{subject} contains environment/service checks that may influence "
                        f"analysis or later execution branches ({anti_detail})."
                        if any(
                            indexes_by_kind.get(kind)
                            for kind in ("mechanism_environment_check", "mechanism_service_query")
                        )
                        else f"{subject} contains indicators associated with anti-analysis checks."
                    ),
                    tuple(anti_indexes[:12]),
                    "MEDIUM",
                    {
                        "technique_id": "T1497",
                        "name": "Virtualization/Sandbox Evasion",
                        "status": "candidate",
                    },
                )
            )

        # A mechanism chain is a higher-value observation than a flat API
        # indicator.  Keep the claim static/inferred and preserve the ordered
        # steps in the statement so report consumers can audit the reasoning.
        for index in chain_indexes:
            value = facts[index].value if isinstance(facts[index].value, dict) else {}
            chain_type = str(value.get("chain_type", "mechanism"))
            categories = [str(item) for item in value.get("categories", [])]
            steps = value.get("steps", [])
            step_names = [
                str(item.get("name"))
                for item in steps
                if isinstance(item, dict) and item.get("name")
            ] if isinstance(steps, list) else []
            module = facts[index].module
            mapping = {
                "loader": {"technique_id": "T1129", "name": "Shared Modules", "status": "candidate"},
                "c2_network": {"technique_id": "T1071", "name": "Application Layer Protocol", "status": "candidate"},
                "anti_analysis": {"technique_id": "T1497", "name": "Virtualization/Sandbox Evasion", "status": "candidate"},
                "execution": {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "status": "candidate"},
            }.get(module, {})
            claims.append(
                ClaimSpec(
                    module,
                    subject,
                    "exhibits_mechanism_chain",
                    chain_type,
                    " -> ".join(categories),
                    "static call/instruction order; runtime execution and intent are not proven",
                    (
                        f"{subject} contains a {chain_type} candidate in the recovered function "
                        f"({', '.join(step_names[:8])}); the ordered observations support "
                        "a mechanism hypothesis, but dynamic behavior remains unverified."
                    ),
                    (index,),
                    "HIGH" if len(categories) >= 3 else "MEDIUM",
                    mapping,
                )
            )

        # Script imports/calls are behavioral signals too.  Promote them into
        # conservative claims so a script is analyzed by mechanism and not
        # merely displayed as a list of AST fragments.
        script_indexes = indexes_by_kind.get("script_import", []) + indexes_by_kind.get(
            "script_call", []
        )
        names = {
            index: str(facts[index].value.get("name", "")).lower()
            for index in script_indexes
        }

        def matching(terms: tuple[str, ...]) -> tuple[int, ...]:
            return tuple(index for index, name in names.items() if any(term in name for term in terms))

        def add_script_claim(
            indexes: tuple[int, ...],
            module: str,
            action: str,
            obj: str,
            mechanism: str,
            condition: str,
            statement: str,
            attack_mapping: dict[str, object],
        ) -> None:
            if not indexes or any(item.module == module for item in claims):
                return
            claims.append(
                ClaimSpec(
                    module,
                    subject,
                    action,
                    obj,
                    mechanism,
                    condition,
                    statement,
                    indexes,
                    "MEDIUM",
                    attack_mapping,
                )
            )

        network_calls = matching(
            (
                "socket",
                "connect",
                "urlopen",
                "request",
                "webclient",
                "invoke-webrequest",
                "http",
                "ftp",
                "dns",
            )
        )
        add_script_claim(
            network_calls,
            "c2_network",
            "may_connect_to_network",
            "remote endpoint",
            "script import or call to network transport APIs",
            "network purpose and endpoint reachability are not confirmed statically",
            f"{subject} contains script imports or calls consistent with network communication.",
            {"technique_id": "T1071", "name": "Application Layer Protocol", "status": "candidate"},
        )
        decode_calls = matching(
            ("b64decode", "base64", "decrypt", "decode", "unmarshal", "decompress", "xor")
        )
        add_script_claim(
            decode_calls,
            "decryption",
            "may_decode_or_decrypt",
            "embedded or transformed data",
            "script decoding, decryption, or decompression API",
            "decoded content and runtime use are not confirmed statically",
            f"{subject} contains script operations consistent with decoding or decryption.",
            {"technique_id": "T1027", "name": "Obfuscated/Compressed Files", "status": "candidate"},
        )
        execution_calls = matching(
            ("subprocess", "popen", "system", "exec", "spawn", "createprocess", "winexec", "shell")
        )
        add_script_claim(
            execution_calls,
            "execution",
            "may_execute",
            "process or command",
            "script process creation or command execution API",
            "runtime execution is not confirmed by static evidence alone",
            f"{subject} contains script operations associated with process or command execution.",
            {
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "status": "candidate",
            },
        )
        loader_calls = matching(
            ("loadlibrary", "getprocaddress", "ctypes", "reflect", "importlib", "webclient")
        )
        add_script_claim(
            loader_calls,
            "loader",
            "may_load_secondary_component",
            "code or a secondary component",
            "script dynamic import, reflection, or loader API",
            "loaded component and execution are not confirmed statically",
            f"{subject} contains script operations associated with loading a secondary component.",
            {"technique_id": "T1129", "name": "Shared Modules", "status": "candidate"},
        )

        return tuple(claims)

    def prioritize_function_evidence(
        self,
        candidates: tuple[FunctionEvidenceCandidate, ...],
        *,
        limit: int = 15,
    ) -> tuple[FunctionReviewClaim, ...]:
        ranked = sorted(
            candidates,
            key=lambda candidate: (
                -(
                    min(candidate.xref_count, 100) * 3
                    + min(candidate.cfg_block_count, 200)
                    + min(candidate.instruction_count // 10, 100)
                ),
                candidate.entry,
            ),
        )
        claims: list[FunctionReviewClaim] = []
        for candidate in ranked[:limit]:
            score = (
                min(candidate.xref_count, 100) * 3
                + min(candidate.cfg_block_count, 200)
                + min(candidate.instruction_count // 10, 100)
            )
            if score <= 0 or not candidate.evidence_ids:
                continue
            if score >= 300:
                confidence = "HIGH"
            elif score >= 100:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"
            claims.append(
                FunctionReviewClaim(
                    subject=candidate.artifact_id,
                    object=f"{candidate.name}@{candidate.entry}",
                    statement=(
                        f"High-value static review candidate {candidate.name} at "
                        f"{candidate.entry}: {candidate.xref_count} Xrefs, "
                        f"{candidate.cfg_block_count} CFG blocks, and "
                        f"{candidate.instruction_count} instructions."
                    ),
                    confidence=confidence,
                    evidence_ids=candidate.evidence_ids,
                )
            )
        return tuple(claims)
