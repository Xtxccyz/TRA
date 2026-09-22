"""Lasting acceptance for the official GET analyst report.

These tests replay the failure mode of the 2026-09-15 DoubleFeatureDll 3080
run: the user received a 137k-character ledger whose 「分析结论」 still dumped
FUN_ call chains, CRT imports, false-positive chapters (lateral movement,
command dispatch from strcmp, DoS/SAM), while coverage said 1/13 mechanisms
were verified (8%).

Official GET markdown must be the analyst document.  The V3 ledger remains
available via document_to_markdown / Evidence Explorer.  Raising the 8%
figure by weakening verifiers is out of scope; the report must explain the
gate instead of hiding recovered facts.
"""

from __future__ import annotations

from types import SimpleNamespace

from threat_report_agent.analyst_report import (
    ANALYST_CONCLUSION_HEADING,
    apply_model_topic_plan,
    plan_analyst_topics,
    primary_analyst_violations,
    render_official_markdown,
    split_analyst_markdown,
    stamp_official_report_chrome,
)
from threat_report_agent.prompts import PromptRegistry
from threat_report_agent.report.reporting import (
    REPORT_V3_REQUIRED_SECTIONS,
    build_report_document,
    document_to_markdown,
)


def _v3_document(*rows: dict[str, object], **overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-analyst",
        "task_id": "task-analyst",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "modules": [
            {
                "id": "static_triage",
                "title": "Static Triage",
                "summary": "",
                "rows": list(rows),
            }
        ],
        "trace": {},
    }
    document.update(overrides)
    return document


def _chapter(official: str, heading: str) -> str:
    marker = f"### {heading}"
    start = 0
    index = -1
    while True:
        found = official.find(marker, start)
        if found < 0:
            return ""
        if found > 0 and official[found - 1] == "#":
            start = found + 1
            continue
        index = found
        break
    body = official[index + len(marker):]
    next_h3 = len(body)
    cursor = 0
    while True:
        found = body.find("\n### ", cursor)
        if found < 0:
            break
        if found + 5 < len(body) and body[found + 5] == "#":
            cursor = found + 1
            continue
        next_h3 = found
        break
    return body[:next_h3]


def _dll_like_document() -> dict[str, object]:
    """Minimised projection of task 972ac8b1 (DoubleFeatureDll 3080 rerun)."""

    dumped_loader_how = (
        "['FUN_18000ee9c@18000ee9c: LoadLibraryA -> GetProcAddress -> memset(RDX + 0x31) "
        "-> sprintf(0x1800641f0) -> FreeLibrary; consumer=LoadLibraryA, GetProcAddress, "
        "FreeLibrary; predicate=JZ 0x18000f080; JNZ 0x18000ef71']"
    )
    return _v3_document(
        {
            "type": "pe_basics",
            "format": "PE32+",
            "machine": "0x8664",
            "entry_rva": "29904",
            "subsystem": "3",
            "section_names": [".text", ".rdata", ".data", ".pdata", ".reloc"],
            "imports": [
                "wcschr", "memcmp", "mbstowcs", "wcscmp", "sprintf",
                "LoadLibraryA", "GetProcAddress", "CreateThread", "CryptDecrypt",
                "FindResourceA", "LoadResource", "LockResource", "SizeofResource",
                "VirtualAlloc", "VirtualQuery", "GetSystemInfo", "QueueUserAPC",
                "TlsAlloc",
            ],
            "sha256": "f265defd87094c95c7d3ddf009d115207cd9d4007cf98629e814eda8798906af",
        },
        {
            "type": "behavior_finding",
            "catalog_id": "loader-and-api-resolution",
            "finding_status": "SUPPORTED",
            "what": "Static analysis recovered a verified dynamic api resolution mechanism.",
            "how": dumped_loader_how,
            "evidence_ids": ["e-loader"],
        },
        {
            "type": "behavior_finding",
            "catalog_id": "thread-and-callback",
            "finding_status": "CANDIDATE",
            "what": "DoubleFeatureDll.dll.standard statically recovers a same-process OS thread.",
            "how": [
                "CreateThread lpStartAddress=0x1800011c0; lpParameter=UNKNOWN(parameter)",
            ],
            "evidence_ids": ["e-thread"],
        },
        {
            "type": "behavior_finding",
            "catalog_id": "config-and-crypto",
            "finding_status": "CANDIDATE",
            "what": "Function contains CryptDecrypt.",
            "how": "FUN_18003be48@18003be48: CryptDecrypt(Final=RAX + 0x1); predicate=JZ 0x18003bf22",
            "evidence_ids": ["e-crypt"],
        },
        {
            "type": "behavior_finding",
            "catalog_id": "unknown_behavior",
            "finding_status": "CANDIDATE",
            "what": "FindResourceA -> LoadResource -> LockResource",
            "how": dumped_loader_how,
            "evidence_ids": ["e-res"],
        },
        {
            "type": "mechanism_candidate",
            "mechanism_id": "mech-loader",
            "mechanism_type": "DYNAMIC_API_RESOLUTION",
            "catalog_id": "loader-and-api-resolution",
            "status": "VERIFIED",
            "target": "dynamic API resolver",
            "inputs": ["LoadLibraryA module name"],
            "transformation_or_control": ["LoadLibraryA -> GetProcAddress -> indirect CALL"],
            "outputs": ["resolved function pointer"],
            "consumers": ["indirect CALL RAX"],
            "side_effects": ["imports resolved outside the static IAT"],
            "evidence_ids": ["e-loader", "e-api"],
            "completeness": 90,
            "verifier": {"status": "VERIFIED"},
        },
        {
            "type": "investigation_seed_map",
            "artifact_id": "artifact-1",
            "cluster_count": 2,
            "clusters": [{"id": "c1", "question": "Which module is resolved?", "evidence_ids": ["e-api"]}],
        },
        analysis_coverage={
            "mechanism_count": 13,
            "verified_mechanism_count": 1,
            "gaps": [
                "Candidate mechanism ratio is 92%; report is bounded until evidence is verified.",
                "Mechanism closure is 8%; unresolved static hypotheses remain.",
                "Static boundary: no new evidence closed the DECODE_CONFIG mechanism; missing evidence: cipher/data.",
                "Static boundary: no new evidence closed the PROCESS_EXECUTION mechanism; missing evidence: creation_flags.",
            ],
        },
    )


def test_analyst_report_prompt_forbids_a_fixed_chapter_outline() -> None:
    registry = PromptRegistry.load_builtin()
    prompt = registry.require("analyst-report-agent", "1.0.0")
    collapsed = " ".join(prompt.system_text.split()).casefold()
    assert "do not emit a fixed c2" in collapsed
    assert "evidence_anchors" in collapsed
    assert "评测基准报告" in prompt.system_text


def test_official_dll_report_is_analyst_prose_not_a_ledger() -> None:
    from threat_report_agent.analyst_report import unmatched_category_statement

    document = _dll_like_document()
    official = render_official_markdown(document)
    ledger = document_to_markdown(document)

    assert ANALYST_CONCLUSION_HEADING in official
    assert "0x1800011c0" in official
    assert "CryptDecrypt" in official
    assert "LoadLibrary" in official or "GetProcAddress" in official
    assert "13 条机制候选" in official
    assert "1 条达到门限" in official or "1 条达到验证器门限" in official
    assert "动态加载与 API 解析" in official
    assert "DYNAMIC_API_RESOLUTION" in official
    assert "密文" in official or "解密" in official
    assert "creation_flags" in official
    assert "UNKNOWN(creation_flags)" in official
    assert "UNKNOWN(consumer)" in official
    assert "Static analysis recovered a verified" not in official
    assert "### 主机发现" not in official
    assert "### 内存分配" not in official

    assert "Investigation Seed Map" not in official
    assert "pipeline completion" not in official.casefold()
    assert "Executive Assessment" not in official
    assert "field completeness" not in official.casefold()
    assert "选题依据" not in official
    assert "wcschr" not in official
    assert "memcmp" not in official
    assert "横向移动" not in official
    assert "命令分发" not in official
    assert "破坏与资源滥用" not in official
    assert "凭据与敏感数据" not in official
    # G4 §8.2-2/§8.4-1：网络通信属必写闭集，未命中时必须点名缺失槽位并声明边界，
    # 不得为了凑篇幅编造 URL/IOC。
    sentence = next(
        line for line in official.splitlines() if line.startswith("未命中：网络通信。")
    )
    assert "UNKNOWN(" in sentence, sentence
    assert "不代表样本不具备该能力" in sentence, sentence
    assert "http://" not in official
    assert "https://" not in official
    assert "FUN_18000ee9c@18000ee9c:" not in official
    assert primary_analyst_violations(official) == []
    assert len(official) < 12_000
    assert "resume.pdf" not in official.casefold()
    assert "foxitpdfreader" not in official.casefold()

    assert "Investigation Seed Map" in ledger
    assert "Which module is resolved" in ledger


def test_tls_callback_opens_a_thread_chapter_even_when_not_in_example_outline() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["TlsAlloc", "CreateThread", "GetProcAddress"],
                "entry_rva": "0x1420",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "thread-and-callback",
                "finding_status": "CANDIDATE",
                "what": "TLS callback and worker thread are present.",
                "how": "TlsAlloc -> CreateThread lpStartAddress=0x401000",
                "evidence_ids": ["e-tls"],
            },
        )
    )
    assert ANALYST_CONCLUSION_HEADING in official
    assert "TLS" in official or "线程" in official
    assert "0x401000" in official
    assert "网络通信" not in official
    assert "C2" not in official
    assert primary_analyst_violations(official) == []


def test_absent_network_evidence_does_not_invent_a_c2_chapter() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateFileW", "WriteFile"],
                "entry_rva": "0x1000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "file-operations",
                "finding_status": "SUPPORTED",
                "what": "The image writes a file path recovered from a static constant.",
                "how": "CreateFileW -> WriteFile path=`C:\\Windows\\Temp\\stage.bin`",
                "evidence_ids": ["e-file"],
            },
        )
    )
    assert "文件" in official
    assert "网络通信" not in official
    assert "持久化" not in official
    assert primary_analyst_violations(official) == []


def test_winhttpopen_listing_without_rebuilt_request_stays_unknown() -> None:
    """C4: WinHttpOpen in HOW is not a reconstructed request and is not live C2."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["WinHttpOpen"],
                "entry_rva": "0x401000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "network-transport",
                "finding_status": "CANDIDATE",
                "what": "WinHttpOpen is imported.",
                "how": "WinHttpOpen",
            },
        )
    )
    assert "UNKNOWN(request)" in official
    assert "活 c2" not in official.casefold()
    assert "beacon" not in official.casefold()
    assert primary_analyst_violations(official) == []


def test_crypto_evidence_opens_an_encoding_chapter_from_catalog_not_a_preset() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CryptDecrypt", "CryptAcquireContextW"],
                "entry_rva": "0x2000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "SUPPORTED",
                "what": "A CryptoAPI decrypt recovers a configuration buffer.",
                "how": "CryptDecrypt alg=CALG_RC4 input=res#101",
                "evidence_ids": ["e-crypt"],
            },
        )
    )
    assert "编码" in official or "配置" in official or "解密" in official
    assert "CryptDecrypt" in official
    assert "网络通信" not in official
    assert "downstream consumer" not in official.casefold()


def test_seed_map_stays_in_the_ledger_not_the_official_report() -> None:
    evidence = SimpleNamespace(
        id="seed-map-analyst",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="investigation",
        kind="investigation_seed_map",
        nature="STATIC_INFERRED",
        value={
            "cluster_count": 1,
            "high_value_cluster_count": 1,
            "clusters": [{
                "id": "cluster-loader",
                "category": "loader",
                "priority": 90,
                "question": "Which module is resolved and where is the pointer consumed?",
                "hypotheses": ["A dynamically resolved loader path exists."],
                "evidence_ids": ["e-api", "e-xref"],
            }],
        },
        anchor={"type": "investigation_seed_map"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-seed-analyst"),
        task=SimpleNamespace(
            id="task-seed-analyst", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
        ),
        artifacts=[], tool_runs=[], evidence=[evidence], claims=[], claim_evidence=[],
        relations=[], gates=[], model_calls=[], selected_modules=["static_triage"],
    )
    official = render_official_markdown(document)
    ledger = document_to_markdown(document)
    assert "Investigation Seed Map" not in official
    assert "Investigation Seed Map" in ledger
    assert "Which module is resolved" in ledger
    assert primary_analyst_violations(official) == []


def test_model_extra_chapter_is_kept_only_when_grounded_in_evidence() -> None:
    document = _v3_document(
        {
            "type": "pe_basics",
            "imports": ["CoCreateInstance", "RegSetValueExW"],
            "entry_rva": "0x3000",
        },
        {
            "type": "behavior_finding",
            "catalog_id": "registry-operations",
            "finding_status": "CANDIDATE",
            "what": "Registry write candidate.",
            "how": "RegSetValueExW",
            "evidence_ids": ["e-reg"],
        },
    )
    base = plan_analyst_topics(document)
    haystack = "CoCreateInstance RegSetValueExW"
    kept = apply_model_topic_plan(
        base,
        [
            {
                "catalog_id": "custom:com-hijack",
                "title": "COM 劫持",
                "evidence_anchors": ["CoCreateInstance"],
            },
            {
                "catalog_id": "custom:invented-c2",
                "title": "伪造的远控",
                "evidence_anchors": ["WinHttpSendRequest", "http://evil.example"],
            },
        ],
        haystack,
    )
    titles = {item.title for item in kept}
    ids = {item.catalog_id for item in kept}
    assert "COM 劫持" in titles
    assert "custom:com-hijack" in ids
    assert "伪造的远控" not in titles
    assert "custom:invented-c2" not in ids
    assert any(item.catalog_id == "registry-operations" for item in kept)
    placeholder = apply_model_topic_plan(
        base,
        [
            {
                "catalog_id": "registry-operations",
                "title": "optional Chinese retitle",
                "evidence_anchors": ["RegSetValueExW"],
            }
        ],
        haystack,
    )
    registry_topic = next(item for item in placeholder if item.catalog_id == "registry-operations")
    assert registry_topic.title == "注册表操作"


def test_apc_import_alone_does_not_open_a_remote_injection_chapter() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["QueueUserAPC", "CreateThread"],
                "entry_rva": "0x1000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "thread-and-callback",
                "finding_status": "CANDIDATE",
                "what": "APC/thread candidate",
                "how": "QueueUserAPC -> CreateThread lpStartAddress=0x401000",
                "evidence_ids": ["e-apc"],
            },
        )
    )
    assert "线程" in official or "APC" in official
    assert "进程注入" not in official
    assert primary_analyst_violations(official) == []


def test_systeminfo_import_is_not_a_host_discovery_chapter() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["GetSystemInfo", "VirtualQuery", "VirtualAlloc"],
                "entry_rva": "0x1000",
            }
        )
    )
    assert "### 主机发现" not in official
    assert "### 内存分配" not in official
    assert "GetSystemInfo" in official or "VirtualAlloc" in official
    assert primary_analyst_violations(official) == []


def test_ntdll_event_pair_imports_are_not_the_behavior_inventory() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32+",
                "machine": "0x8664",
                "entry_rva": "29904",
                "imports": [
                    "NtCreateEventPair", "NtWaitLowEventPair", "NtSetHighEventPair",
                    "TlsAlloc", "QueueUserAPC", "NtQuerySystemInformation",
                ],
            },
            {
                "type": "behavior_finding",
                "catalog_id": "thread-and-callback",
                "finding_status": "CANDIDATE",
                "how": ["CreateThread lpStartAddress=0x1800011c0"],
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "CANDIDATE",
                "how": "CryptDecrypt",
            },
        )
    )
    assert "NtCreateEventPair" not in official
    assert "NtWaitLowEventPair" not in official
    assert "NtQuerySystemInformation" in official
    assert "CreateThread" in official
    assert "CryptDecrypt" in official
    assert "导入表不能当成功能清单" in official
    assert primary_analyst_violations(official) == []


def test_xor_plaintext_without_consumer_stays_unknown_in_official_conclusion() -> None:
    """Increment 1 S0: recovered XOR HOW is visible; missing consumer is UNKNOWN."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32",
                "imports": ["lstrlenA"],
                "entry_rva": "0x1460",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "CANDIDATE",
                "what": "XOR config decode recovered a URL buffer without a linked consumer.",
                "how": (
                    "key_table_modulo_xor_counter plaintext=`http://69.48.228.74/miaom-c.pdf` "
                    "consumer=UNKNOWN(consumer)"
                ),
                "evidence_ids": ["e-xor"],
            },
            {
                "type": "mechanism_candidate",
                "mechanism_id": "mech-xor",
                "mechanism_type": "DECODE_CONFIG",
                "catalog_id": "config-and-crypto",
                "status": "CANDIDATE",
                "target": "xor config",
                "inputs": ["encoded config block"],
                "transformation_or_control": ["key_table_modulo_xor_counter"],
                "outputs": ["http://69.48.228.74/miaom-c.pdf"],
                "consumers": ["UNKNOWN(consumer)"],
                "evidence_ids": ["e-xor"],
                "verifier": {"status": "CANDIDATE", "missing": ["consumer"]},
            },
        )
    )
    assert ANALYST_CONCLUSION_HEADING in official
    assert "key_table_modulo_xor_counter" in official
    assert "http://69.48.228.74/miaom-c.pdf" in official
    assert "UNKNOWN(consumer)" in official
    assert "管线已坐实" not in official
    assert "decoded output consumer" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_xor_named_api_consumer_is_not_rewritten_as_unknown() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32",
                "imports": ["WinHttpOpen"],
                "entry_rva": "0x1460",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "SUPPORTED_STATIC",
                "how": (
                    "key_table_modulo_xor_counter plaintext=`http://example.invalid/gate` "
                    "consumer=WinHttpOpen"
                ),
            },
        )
    )
    assert "key_table_modulo_xor_counter" in official
    assert "WinHttpOpen" in official
    assert "UNKNOWN(consumer)" not in official
    assert "管线已坐实" not in official
    assert primary_analyst_violations(official) == []


def test_xor_url_joined_static_winhttp_is_visible_but_not_live_c2() -> None:
    """C3: XOR URL HOW with join=JOINED_STATIC consumer=WinHttpOpen is in 编码章, not live C2."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32",
                "imports": ["LoadLibraryW", "GetProcAddress"],
                "entry_rva": "0x1460",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "SUPPORTED_STATIC",
                "how": (
                    "key_table_modulo_xor_counter "
                    "plaintext=`http://69.48.228.74/miaom-c.pdf` "
                    "join=JOINED_STATIC consumer=WinHttpOpen"
                ),
            },
        )
    )
    crypto = _chapter(official, "编码、解密与配置还原")
    assert ANALYST_CONCLUSION_HEADING in official
    assert crypto
    assert "JOINED_STATIC" in crypto
    assert "WinHttpOpen" in crypto
    assert "http://69.48.228.74/miaom-c.pdf" in crypto
    assert "UNKNOWN(join)" not in crypto
    assert "UNKNOWN(consumer)" not in official
    assert "不是活 C2" in official or "不是当时存活的 C2" in official
    assert "c2 active" not in official.casefold()
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_xor_url_named_winhttp_consumer_is_visible_in_official_conclusion() -> None:
    """C3: XOR plaintext URL → named WinHTTP consumer is visible in 「分析结论」."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32",
                "imports": ["LoadLibraryW", "GetProcAddress"],
                "entry_rva": "0x1460",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "SUPPORTED_STATIC",
                "how": (
                    "key_table_modulo_xor_counter "
                    "plaintext=`http://69.48.228.74/miaom-c.pdf` consumer=WinHttpOpen"
                ),
            },
        )
    )
    crypto = _chapter(official, "编码、解密与配置还原")
    assert ANALYST_CONCLUSION_HEADING in official
    assert "http://69.48.228.74/miaom-c.pdf" in crypto
    assert "WinHttpOpen" in crypto
    assert "UNKNOWN(consumer)" not in official
    assert "c2 active" not in official.casefold()
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_xor_url_without_consumer_is_not_live_c2_in_official_conclusion() -> None:
    """C3: XOR URL with no consumer stays UNKNOWN(consumer); HTTP ≠ live C2."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32",
                "imports": ["lstrlenA"],
                "entry_rva": "0x1460",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "CANDIDATE",
                "how": (
                    "key_table_modulo_xor_counter "
                    "plaintext=`http://69.48.228.74/miaom-c.pdf` consumer=UNKNOWN(consumer)"
                ),
            },
        )
    )
    crypto = _chapter(official, "编码、解密与配置还原")
    assert ANALYST_CONCLUSION_HEADING in official
    assert "UNKNOWN(consumer)" in crypto
    assert "http://69.48.228.74/miaom-c.pdf" in crypto
    assert "不是活 C2" in official or "不是当时存活的 C2" in official
    assert "c2 active" not in official.casefold()
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_cryptoapi_joined_static_virtualalloc_is_not_payload_executed() -> None:
    """C3: CryptoAPI HOW with join=JOINED_STATIC consumer=VirtualAlloc is visible, not executed."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32+",
                "imports": ["CryptDecrypt", "VirtualAlloc"],
                "entry_rva": "0x2000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "SUPPORTED_STATIC",
                "how": (
                    "CryptDecrypt output_buffer=0x14005a000 "
                    "join=JOINED_STATIC consumer=VirtualAlloc"
                ),
            },
        )
    )
    crypto = _chapter(official, "编码、解密与配置还原")
    assert ANALYST_CONCLUSION_HEADING in official
    assert crypto
    assert "JOINED_STATIC" in crypto
    assert "VirtualAlloc" in crypto
    assert "CryptDecrypt" in crypto
    assert "UNKNOWN(join)" not in crypto
    assert "UNKNOWN(consumer)" not in crypto
    assert "载荷已执行" not in official
    assert "DYNAMIC_OBSERVED" not in official
    assert "DYNAMIC" not in crypto
    assert "已运行" not in crypto
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_cryptoapi_output_without_join_does_not_claim_payload_executed() -> None:
    """C3: CryptoAPI output without join must not say 载荷已执行 / 已运行 / DYNAMIC."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32+",
                "imports": ["CryptDecrypt", "VirtualAlloc"],
                "entry_rva": "0x2000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "CANDIDATE",
                "how": (
                    "CryptDecrypt output_buffer=0x14005a000 "
                    "consumer=UNKNOWN(consumer) join=UNKNOWN(join)"
                ),
            },
        )
    )
    crypto = _chapter(official, "编码、解密与配置还原")
    assert ANALYST_CONCLUSION_HEADING in official
    assert "CryptDecrypt" in crypto
    assert "UNKNOWN(join)" in crypto or "UNKNOWN(consumer)" in crypto
    assert "UNKNOWN(join)" in official
    assert "载荷已执行" not in official
    assert "DYNAMIC_OBSERVED" not in official
    assert "DYNAMIC" not in crypto
    assert "已运行" not in crypto
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_process_creation_without_flags_stays_unknown_in_official_conclusion() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32+",
                "imports": ["CreateProcessW"],
                "entry_rva": "0x1000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "what": "CreateProcessW is imported; creation flags were not recovered.",
                "how": "CreateProcessW command=`FoxitPDFReader.exe` creation_flags=UNKNOWN(creation_flags)",
            },
        )
    )
    assert "CreateProcessW" in official or "进程创建" in official
    assert "UNKNOWN(creation_flags)" in official
    assert "CREATE_SUSPENDED" not in official
    assert primary_analyst_violations(official) == []


def test_ppid_explorer_string_without_process32_stays_unknown_in_official_conclusion() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["UpdateProcThreadAttribute", "CreateProcessW"],
                "entry_rva": "0x2000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "parent-process-spoofing",
                "finding_status": "CANDIDATE",
                "what": "Parent attribute API without Process32 enumeration.",
                "how": "UpdateProcThreadAttribute attribute=0x20000 parent=UNKNOWN(parent identity)",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "parent-process-spoofing",
                "finding_status": "CANDIDATE",
                "how": "string explorer.exe is not parent identity",
            },
        )
    )
    assert "UNKNOWN(parent" in official
    assert "explorer.exe" not in official.casefold()
    assert "注入" not in official
    assert primary_analyst_violations(official) == []


def test_create_thread_without_start_routine_is_not_injection_in_official_conclusion() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateThread"],
                "entry_rva": "0x3000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "thread-and-callback",
                "finding_status": "CANDIDATE",
                "what": "CreateThread import without recovered start routine.",
                "how": "CreateThread",
            },
        )
    )
    assert "CreateThread" in official or "线程" in official
    assert "远程注入" not in official
    assert primary_analyst_violations(official) == []


def test_createprocessw_present_without_flags_field_stays_unknown() -> None:
    """CreateProcessW listed with no recovered flags is UNKNOWN, never CREATE_SUSPENDED."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32+",
                "imports": ["CreateProcessW"],
                "entry_rva": "0x1000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "what": "CreateProcessW call is present.",
                "how": "CreateProcessW",
            },
        )
    )
    assert "CreateProcessW" in official or "进程创建" in official
    assert "UNKNOWN(creation_flags)" in official
    assert "CREATE_SUSPENDED" not in official
    assert "CREATE_NEW_CONSOLE" not in official
    assert "UNKNOWN(fallback)" in official
    assert primary_analyst_violations(official) == []


def test_create_thread_listed_without_start_routine_stays_unknown() -> None:
    """A CreateThread listing is not a closed thread HOW when start_routine is missing."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateThread"],
                "entry_rva": "0x3000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "thread-and-callback",
                "finding_status": "CANDIDATE",
                "what": "CreateThread is listed.",
                "how": "CreateThread",
            },
        )
    )
    thread_section = official
    if "### 线程" in official:
        thread_section = official.split("### 线程", 1)[1].split("\n### ", 1)[0]
    assert "CreateThread" in official or "线程" in official
    assert (
        "UNKNOWN(start_routine)" in thread_section
        or "UNKNOWN(entry)" in thread_section
    )
    assert "静态恢复到同进程" not in thread_section
    assert "lpStartAddress=" not in thread_section
    assert "远程注入" not in official
    assert primary_analyst_violations(official) == []


def test_ppid_without_process32_chain_does_not_treat_explorer_as_parent() -> None:
    """PPID without Process32 enumeration must not present explorer.exe as proven parent."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["UpdateProcThreadAttribute", "CreateProcessW"],
                "entry_rva": "0x2000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "parent-process-spoofing",
                "finding_status": "CANDIDATE",
                "what": "Parent attribute API without Process32 enumeration.",
                "how": "UpdateProcThreadAttribute parent=explorer.exe",
            },
        )
    )
    parent_section = official
    if "### 父进程" in official:
        parent_section = official.split("### 父进程", 1)[1].split("\n### ", 1)[0]
    assert "UNKNOWN(parent" in official
    assert "父镜像 `explorer.exe`" not in parent_section.casefold()
    assert "explorer.exe" not in official.casefold()
    assert "注入" not in official
    assert primary_analyst_violations(official) == []


def test_xor_and_process_without_join_stay_unknown_in_official_conclusion() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateProcessW"],
                "entry_rva": "0x1000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "CANDIDATE",
                "how": "key_table_modulo_xor_counter plaintext=`FoxitPDFReader.exe` consumer=UNKNOWN(consumer)",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "how": "CreateProcessW command=`FoxitPDFReader.exe` creation_flags=0x000f4240 join=UNKNOWN(join)",
            },
        )
    )
    assert "UNKNOWN(join)" in official
    assert "UNKNOWN(consumer)" in official
    assert primary_analyst_violations(official) == []


def test_same_buffer_join_is_visible_in_official_conclusion() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateProcessW"],
                "entry_rva": "0x1000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "SUPPORTED_STATIC",
                "how": "key_table_modulo_xor_counter plaintext=`FoxitPDFReader.exe` consumer=UNKNOWN(consumer)",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "how": "CreateProcessW command=`FoxitPDFReader.exe` creation_flags=0x000f4240 join=JOINED_STATIC",
            },
        )
    )
    assert "JOINED_STATIC" in official or "同一对象" in official
    assert "UNKNOWN(join)" not in official
    assert primary_analyst_violations(official) == []


def test_xor_plaintext_task_name_is_visible_with_joined_createprocess() -> None:
    """C3: XOR plaintext → CreateProcess JOINED_STATIC shows the task name and join slot."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateProcessW"],
                "entry_rva": "0x1000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "SUPPORTED_STATIC",
                "how": (
                    "key_table_modulo_xor_counter plaintext=`FoxitPDFReader.exe` "
                    "consumer=CreateProcessW"
                ),
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "how": (
                    "CreateProcessW command=`FoxitPDFReader.exe` "
                    "creation_flags=0x000f4240 join=JOINED_STATIC"
                ),
            },
        )
    )
    crypto = _chapter(official, "编码、解密与配置还原")
    process = _chapter(official, "进程创建")
    assert ANALYST_CONCLUSION_HEADING in official
    assert "FoxitPDFReader.exe" in crypto
    assert "CreateProcessW" in crypto
    assert "JOINED_STATIC" in process
    assert "UNKNOWN(join)" not in official
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_process_task_name_without_join_stays_unknown_in_official_conclusion() -> None:
    """C3: process track must not present FoxitPDFReader.exe without a join slot."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateProcessW"],
                "entry_rva": "0x1000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "how": "CreateProcessW command=`FoxitPDFReader.exe` creation_flags=0x000f4240",
            },
        )
    )
    process = _chapter(official, "进程创建")
    assert ANALYST_CONCLUSION_HEADING in official
    assert "UNKNOWN(join)" in process
    if "FoxitPDFReader.exe" in process:
        assert "UNKNOWN(join)" in process
    assert "JOINED_STATIC" not in official
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_failed_join_does_not_invent_resume_pdf_task_name() -> None:
    """C3: failed join stays UNKNOWN(join); process track does not invent Resume.pdf."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateProcessW"],
                "entry_rva": "0x1000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "CANDIDATE",
                "how": (
                    "key_table_modulo_xor_counter "
                    "plaintext=`http://example.invalid/gate` "
                    "consumer=UNKNOWN(consumer) join=UNKNOWN(join)"
                ),
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "how": "CreateProcessW creation_flags=0x000f4240 join=UNKNOWN(join)",
            },
        )
    )
    crypto = _chapter(official, "编码、解密与配置还原")
    process = _chapter(official, "进程创建")
    assert ANALYST_CONCLUSION_HEADING in official
    assert "UNKNOWN(join)" in crypto or "UNKNOWN(join)" in process
    assert "UNKNOWN(join)" in process
    assert "命令 `Resume.pdf`" not in process
    assert "Resume.pdf" not in official
    assert "JOINED_STATIC" not in official
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_resume_pdf_command_without_join_is_not_an_independent_task_name() -> None:
    """C3: process track must not present Resume.pdf as a discovered task without join."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateProcessW"],
                "entry_rva": "0x1000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "how": "CreateProcessW command=`Resume.pdf` creation_flags=0x000f4240",
            },
        )
    )
    process = _chapter(official, "进程创建")
    assert ANALYST_CONCLUSION_HEADING in official
    assert "UNKNOWN(join)" in process
    assert "命令 `Resume.pdf`" not in process
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_official_conclusion_omits_persisted_investigation_and_fun_ledger() -> None:
    """S0: official GET conclusion must not dump PERSISTED_INVESTIGATION or FUN_ names."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateProcessW", "CryptDecrypt"],
                "entry_rva": "0x1000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "CANDIDATE",
                "how": (
                    "key_table_modulo_xor_counter plaintext=`http://example.invalid/x` "
                    "consumer=UNKNOWN(consumer) PERSISTED_INVESTIGATION FUN_140004605"
                ),
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "how": (
                    "CreateProcessW command=`FoxitPDFReader.exe` creation_flags=0x000f4240 "
                    "join=UNKNOWN(join) PERSISTED_INVESTIGATION FUN_140004605"
                ),
            },
        )
    )
    assert ANALYST_CONCLUSION_HEADING in official
    assert "UNKNOWN(consumer)" in official
    assert "UNKNOWN(join)" in official
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_thread_start_without_body_stays_unknown_loop_and_exit() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateThread"],
                "entry_rva": "0x3000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "thread-and-callback",
                "finding_status": "CANDIDATE",
                "how": "CreateThread lpStartAddress=0x140001500 lpParameter=UNKNOWN(parameter)",
            },
        )
    )
    assert "0x140001500" in official
    assert "UNKNOWN(loop)" in official
    assert "UNKNOWN(exit)" in official
    assert "不是远程注入" in official
    assert primary_analyst_violations(official) == []


def test_environment_probe_without_threshold_stays_unknown_in_official_conclusion() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["IsDebuggerPresent", "GetTickCount"],
                "entry_rva": "0x4000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "environment-guard",
                "finding_status": "CANDIDATE",
                "how": "IsDebuggerPresent threshold=UNKNOWN(threshold)",
            },
        )
    )
    assert "UNKNOWN(threshold)" in official
    assert "不能写成已证实的反分析门控" in official
    assert primary_analyst_violations(official) == []


def test_network_url_without_transport_is_not_live_c2_in_official_conclusion() -> None:
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["LoadLibraryW"],
                "entry_rva": "0x5000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "network-transport",
                "finding_status": "CANDIDATE",
                "how": "string http://example.invalid/path UNKNOWN(request)",
            },
        )
    )
    assert "UNKNOWN(request)" in official
    assert "c2 active" not in official.casefold()
    assert primary_analyst_violations(official) == []


def test_sleep_with_back_edge_is_loop_chapter_not_c2_tasking() -> None:
    """C4: recovered Sleep + real back_edge opens the loop chapter, still not C2 tasking."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["Sleep"],
                "entry_rva": "0x6000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "communication-loop",
                "finding_status": "SUPPORTED_STATIC",
                "how": "Sleep delay=1000 back_edge=0x140001abc",
            },
        )
    )
    loop = _chapter(official, "通信循环与心跳")
    assert ANALYST_CONCLUSION_HEADING in official
    assert loop
    assert "Sleep" in loop
    assert "1000" in loop
    assert "0x140001abc" in loop
    assert "UNKNOWN(loop)" not in loop
    assert "c2 tasking" not in official.casefold()
    assert "tasking" not in official.casefold()
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_sleep_without_back_edge_is_unknown_loop_not_c2_tasking() -> None:
    """C4: Sleep/delay listing without a back-edge is UNKNOWN(loop), not C2 tasking."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["Sleep"],
                "entry_rva": "0x6000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "communication-loop",
                "finding_status": "CANDIDATE",
                "what": "Sleep is listed without a recovered control-flow back-edge.",
                "how": (
                    "Sleep delay=1000 back_edge=UNKNOWN(loop) "
                    "PERSISTED_INVESTIGATION FUN_140004605"
                ),
            },
        )
    )
    loop = _chapter(official, "通信循环与心跳")
    assert ANALYST_CONCLUSION_HEADING in official
    assert loop
    assert "UNKNOWN(loop)" in loop
    assert "c2 tasking" not in official.casefold()
    assert "tasking" not in official.casefold()
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_tmp_mz_without_size_threshold_is_not_dropped() -> None:
    """C4: .tmp / MZ without size 0x1000 stays UNKNOWN(size); filename is not 已落地."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateFileW", "WriteFile"],
                "entry_rva": "0x8000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "file-operations",
                "finding_status": "CANDIDATE",
                "what": "A .tmp name and MZ magic are listed without a recovered size threshold.",
                "how": (
                    "CreateFileW path=`stage.tmp` MZ "
                    "PERSISTED_INVESTIGATION FUN_140004605"
                ),
            },
        )
    )
    files = _chapter(official, "文件操作")
    assert ANALYST_CONCLUSION_HEADING in official
    assert files
    assert "UNKNOWN(size)" in files or "UNKNOWN(threshold)" in files
    assert "size=0x1000" not in files.casefold()
    assert "已落地" not in official
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_official_conclusion_does_not_invent_empty_phase_shells() -> None:
    """C4: official GET must not invent Phase 1–8 empty shells. Keep S0."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateProcessW"],
                "entry_rva": "0x1460",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "how": (
                    "CreateProcessW creation_flags=UNKNOWN(creation_flags) "
                    "PERSISTED_INVESTIGATION FUN_140004605"
                ),
            },
        )
    )
    assert ANALYST_CONCLUSION_HEADING in official
    for index in range(1, 9):
        assert f"Phase {index}" not in official
    assert "startup / loader" not in official
    assert "UNKNOWN(phase not recovered statically)" not in official
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_defender_dword_is_visible_but_not_whole_product_off() -> None:
    """C4: recovered DWORD on a Defender key is visible, never 关闭整个 Defender / 永不扫描."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["RegSetValueExW"],
                "entry_rva": "0x7000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "defense-evasion",
                "finding_status": "SUPPORTED_STATIC",
                "how": (
                    "RegSetValueExW key=`SOFTWARE\\Microsoft\\Windows Defender` "
                    "dword=0x1"
                ),
            },
        )
    )
    evasion = _chapter(official, "防御规避")
    assert ANALYST_CONCLUSION_HEADING in official
    assert evasion
    assert "0x1" in evasion
    assert "UNKNOWN(value)" not in evasion
    assert "永不扫描" not in official
    assert "关闭整个 Defender" not in official
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_defender_key_without_dword_stays_unknown_value() -> None:
    """C4: Defender registry key without DWORD value is UNKNOWN(value), not 永不扫描."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["RegSetValueExW"],
                "entry_rva": "0x7000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "defense-evasion",
                "finding_status": "CANDIDATE",
                "what": "A Defender-related registry key is listed without a recovered DWORD.",
                "how": (
                    "RegSetValueExW key=`SOFTWARE\\Microsoft\\Windows Defender` "
                    "value=UNKNOWN(value) PERSISTED_INVESTIGATION FUN_140004605"
                ),
            },
        )
    )
    evasion = _chapter(official, "防御规避")
    assert ANALYST_CONCLUSION_HEADING in official
    assert evasion
    assert "UNKNOWN(value)" in evasion
    assert "永不扫描" not in official
    assert "关闭整个 Defender" not in official
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_official_conclusion_projects_ten_question_slots_and_keeps_unknowns() -> None:
    """C7: GET 「分析结论」 projects ten-question slots; empty text is not filled."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateProcessW"],
                "entry_rva": "0x1000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "what": "CreateProcessW is present.",
                "how": "CreateProcessW creation_flags=UNKNOWN(creation_flags)",
                "target": " ",
                "condition": "",
                "output": "UNKNOWN(output)",
                "consumer": "UNKNOWN(consumer)",
                "unknowns": ["UNKNOWN(join)"],
            },
        )
    )
    conclusion = official.split(ANALYST_CONCLUSION_HEADING, 1)[1]
    summary = _chapter(official, "结论摘要")
    assert ANALYST_CONCLUSION_HEADING in official
    assert "- What:" in conclusion
    assert "- How:" in conclusion
    assert "- Target:" in conclusion
    assert "- Condition:" in conclusion
    assert "- Output:" in conclusion
    assert "- Consumer:" in conclusion
    assert "UNKNOWN(target)" in conclusion
    assert "UNKNOWN(condition)" in conclusion
    assert "UNKNOWN(creation_flags)" in conclusion
    assert "UNKNOWN(consumer)" in conclusion
    assert "UNKNOWN(join)" in conclusion or "UNKNOWN(join)" in summary
    assert "UNKNOWN" in summary
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_candidate_findings_stay_candidate_and_are_not_high_risk() -> None:
    """C7: CANDIDATE stays candidate in GET; HIGH risk is not module-count."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["LoadLibraryA", "WinHttpOpen", "CryptDecrypt"],
                "entry_rva": "0x2000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "loader-and-api-resolution",
                "finding_status": "CANDIDATE",
                "what": "LoadLibraryA",
                "how": "",
                "confidence": "HIGH",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "CANDIDATE",
                "what": "CryptDecrypt listing",
                "how": "CryptDecrypt",
                "confidence": "HIGH",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "network-transport",
                "finding_status": "CANDIDATE",
                "what": "WinHttpOpen listing",
                "how": "WinHttpOpen UNKNOWN(request)",
                "confidence": "HIGH",
            },
        )
    )
    conclusion = official.split(ANALYST_CONCLUSION_HEADING, 1)[1]
    assert "CANDIDATE" in conclusion
    assert "已过验证器门限" not in _chapter(official, "动态加载与 API 解析")
    assert "高风险" not in official
    assert "risk=HIGH" not in official.casefold()
    assert "**HIGH**" not in official
    assert primary_analyst_violations(official) == []


def test_official_conclusion_omits_source_org_without_attribution_evidence() -> None:
    """C7: no source org/APT in official conclusion without evidence."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateFileW"],
                "entry_rva": "0x3000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "file-operations",
                "finding_status": "CANDIDATE",
                "what": "The sample is attributed to APT29.",
                "how": "CreateFileW path=`C:\\Temp\\stage.bin` family=APT29",
            },
        )
    )
    assert "APT29" not in official
    assert "APT-29" not in official
    assert primary_analyst_violations(official) == []


def test_api_name_alone_is_not_a_filled_behavior_in_official_conclusion() -> None:
    """C7/M06: API ≠ behavior. Empty how is not a filled slot."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["LoadLibraryA"],
                "entry_rva": "0x1111",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "loader-and-api-resolution",
                "finding_status": "CANDIDATE",
                "what": "LoadLibraryA",
                "how": "",
                "condition": "",
                "output": "",
                "consumer": "",
            },
        )
    )
    slots = _chapter(official, "十问槽位")
    assert "CANDIDATE" in official
    assert "UNKNOWN(how)" in slots or "UNKNOWN(transformation)" in slots
    assert "UNKNOWN(consumer)" in slots
    assert "已过验证器门限" not in _chapter(official, "动态加载与 API 解析")
    assert primary_analyst_violations(official) == []


def test_http_string_is_not_live_c2_in_official_conclusion() -> None:
    """C7/M06: HTTP ≠ live C2."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["LoadLibraryW"],
                "entry_rva": "0x5000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "network-transport",
                "finding_status": "CANDIDATE",
                "what": "HTTP URL string",
                "how": "string http://example.invalid/gate UNKNOWN(request)",
            },
        )
    )
    network = _chapter(official, "网络通信")
    assert "UNKNOWN(request)" in official
    assert "活 C2" not in official
    assert "正在通信" not in official
    assert "c2 active" not in official.casefold()
    assert "beacon" not in network.casefold()
    assert primary_analyst_violations(official) == []


def test_registry_or_task_string_is_not_persistence_in_official_conclusion() -> None:
    """C7/M06: registry/task ≠ persistence."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["RegSetValueExW"],
                "entry_rva": "0x5100",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "registry-operations",
                "finding_status": "CANDIDATE",
                "what": "Registry write",
                "how": "RegSetValueExW key=`Software\\Microsoft\\Windows\\CurrentVersion\\Run`",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "persistence",
                "finding_status": "CANDIDATE",
                "what": "Scheduled task string",
                "how": "schtasks /create UNKNOWN(lifetime)",
            },
        )
    )
    registry = _chapter(official, "注册表操作")
    persist = _chapter(official, "持久化")
    assert registry
    assert persist
    assert "不能把注册表 API 单独写成持久化" in registry
    assert "UNKNOWN(lifetime)" in persist
    assert "已安装的持久化" in persist
    assert "successfully persisted" not in official.casefold()
    assert primary_analyst_violations(official) == []


def test_ppid_and_apc_are_not_injection_in_official_conclusion() -> None:
    """C7/M06: PPID/APC ≠ injection."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["QueueUserAPC", "UpdateProcThreadAttribute"],
                "entry_rva": "0x5200",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "parent-process-spoofing",
                "finding_status": "CANDIDATE",
                "what": "PPID string",
                "how": "UpdateProcThreadAttribute parent=explorer.exe UNKNOWN(parent identity)",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "thread-and-callback",
                "finding_status": "CANDIDATE",
                "what": "QueueUserAPC",
                "how": "QueueUserAPC same-process APC",
            },
        )
    )
    ppid = _chapter(official, "父进程伪装（PPID）")
    thread = _chapter(official, "线程、TLS 回调与 APC")
    assert "UNKNOWN(parent identity)" in ppid
    assert "进程注入" not in official
    assert "远程注入" not in ppid
    assert "远程注入" not in thread
    assert primary_analyst_violations(official) == []


def test_collection_without_sink_is_not_exfil_in_official_conclusion() -> None:
    """C7/M06: collection ≠ exfil."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["OpenClipboard"],
                "entry_rva": "0x5300",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "collection-and-exfiltration",
                "finding_status": "CANDIDATE",
                "what": "Clipboard collection candidate",
                "how": "OpenClipboard collection_source=clipboard",
            },
        )
    )
    collection = _chapter(official, "收集与外传")
    assert collection
    assert "收集不等于外传" in collection
    assert "已经外传" in collection
    assert "exfiltrated" not in official.casefold()
    assert primary_analyst_violations(official) == []


def test_emulation_observed_is_not_runtime_infection_in_official_conclusion() -> None:
    """C7/M06: EMULATION_OBSERVED ≠ 已运行/已感染."""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CryptDecrypt"],
                "entry_rva": "0x5400",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "CANDIDATE",
                "what": "Isolated emulator recovered an XOR window.",
                "how": "EMULATION_OBSERVED key_table_modulo_xor_counter",
                "evidence_natures": ["EMULATION_OBSERVED"],
            },
        )
    )
    summary = _chapter(official, "结论摘要")
    assert "EMULATION_OBSERVED" in official
    assert "已运行" not in official
    assert "已感染" not in official
    assert "不是目标主机上的运行时执行" in summary
    assert primary_analyst_violations(official) == []


def test_chat_summary_and_official_get_share_authoritative_revision_id() -> None:
    """C7: compact chat context and GET share the same authoritative_revision_id."""
    from threat_report_agent.analyst_report import compact_analyst_context

    document = _v3_document(
        {
            "type": "pe_basics",
            "imports": ["CreateProcessW"],
            "entry_rva": "0x1000",
        },
        {
            "type": "behavior_finding",
            "catalog_id": "process-creation",
            "finding_status": "CANDIDATE",
            "how": "CreateProcessW creation_flags=UNKNOWN(creation_flags)",
        },
        authoritative_revision_id="rev-c7-shared",
    )
    official = render_official_markdown(document)
    context = compact_analyst_context(document)
    assert context["authoritative_revision_id"] == "rev-c7-shared"
    assert "`rev-c7-shared`" in official
    assert primary_analyst_violations(official) == []


def test_official_get_scrubs_ledger_uuids_instead_of_failing_synthesis() -> None:
    """C10: Resume-scale HOW/ten-question text may cite Evidence IDs.

    Live task 912c3309 failed REPORT_SYNTHESIS_FAILURE because the official
    GET body still contained Evidence/ledger UUIDs. Header case/task/revision
    IDs stay; the 分析结论 body must not, and synthesis must still emit GET.
    """

    evidence_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    claim_id = "ffffffff-1111-4222-8333-444444444444"
    case_id = "40818ff4-278b-413a-bce8-e781e5f72247"
    task_id = "912c3309-7a12-4394-ab09-a27b368d7744"
    document = _v3_document(
        {
            "type": "pe_basics",
            "imports": ["CreateProcessW"],
            "entry_rva": "0x140001000",
            "sha256": "6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145",
            "path": "Resume.pdf.exe.VIR",
        },
        {
            "type": "behavior_finding",
            "catalog_id": "process-creation",
            "finding_status": "CANDIDATE",
            "what": f"CreateProcessW command=`FoxitPDFReader.exe` evidence={evidence_id}",
            "how": (
                "CreateProcessW command=`FoxitPDFReader.exe`; "
                f"creation_flags=0x00080000; evidence_id={evidence_id}"
            ),
            "claim_id": claim_id,
            "evidence_ids": [evidence_id],
            "completeness": {"evidence_ids": [evidence_id], "claim_id": claim_id},
        },
        case_id=case_id,
        task_id=task_id,
        analyst_model_plan=[
            {
                "catalog_id": "process-creation",
                "title": f"进程创建 {evidence_id}",
                "evidence_anchors": [evidence_id, "CreateProcessW"],
            }
        ],
    )
    official = render_official_markdown(document)
    # G4 §8.2-4/§8.2-5：Evidence/ledger UUID 进调查附录，主文（分析结论）不得出现。
    primary, appendix = split_analyst_markdown(official)
    assert ANALYST_CONCLUSION_HEADING in official
    assert f"`{case_id}`" in official
    assert f"`{task_id}`" in official
    assert evidence_id not in primary
    assert claim_id not in primary
    assert appendix.strip()
    assert "FoxitPDFReader.exe" in official
    # G5 §9.3：正文只展示说得通的 flags；0x000f4240 这类超时常量不得被当成已恢复。
    assert "0x00080000" in official
    assert "`creation_flags`" in official
    assert "creation_flags0x00080000" not in official
    assert primary_analyst_violations(official) == []


def test_official_get_does_not_claim_unknown_flags_when_how_recovered_them() -> None:
    """C10: coverage.gaps must not contradict recovered CreateProcess flags.

    G0 §4.5: the example value is a *credible* flag word. ``0x000f4240`` is
    1,000,000 ms (a WaitForSingleObject timeout) that merely happens to set bit
    19, so it is no longer presented as a recovered flag; that case is covered by
    ``test_implausible_immediate_is_not_a_recovered_creation_flag``.
    """

    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["CreateProcessW"],
                "entry_rva": "0x140001000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "what": "CreateProcessW command=`FoxitPDFReader.exe`",
                "how": (
                    "CreateProcessW command=`FoxitPDFReader.exe`; "
                    "creation_flags=0x00080000; fallback=UNKNOWN(fallback)"
                ),
            },
            analysis_coverage={
                "mechanism_count": 8,
                "verified_mechanism_count": 1,
                "gaps": [
                    "PROCESS_EXECUTION missing creation_flags",
                    "DECODE_CONFIG missing consumer",
                ],
            },
        )
    )
    assert "0x00080000" in official
    assert "进程创建验证未闭合：`UNKNOWN(creation_flags)` 等参数未恢复" not in official
    assert "UNKNOWN(consumer)" in official
    assert primary_analyst_violations(official) == []


def test_verified_finding_with_unknown_request_is_not_verifier_threshold() -> None:
    """C10: UNKNOWN(request) cannot keep 已过验证器门限 just because persist said VERIFIED."""

    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "imports": ["WinHttpSendRequest", "GetProcAddress"],
                "entry_rva": "0x140001000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "network-transport",
                "finding_status": "VERIFIED",
                "what": "network-transport Resume.pdf.exe.VIR",
                "how": "decode_result",
                "consumer": "WinHttpSendRequest",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "thread-and-callback",
                "finding_status": "VERIFIED",
                "what": "thread-and-callback Resume.pdf.exe.VIR",
                "how": [
                    "FUN_140038ae0@140038ae0: TlsGetValue(dword ptr [0x14005d078])"
                ],
                "output": ["0x140038ae0"],
                "consumer": ["0x140038ae0"],
                "ten_question_protocol": {
                    "initiator": {
                        "status": "ANSWERED",
                        "value": "CreateThread",
                    },
                    "transformation": {
                        "status": "UNANSWERED",
                        "value": "",
                    },
                    "output": {
                        "status": "ANSWERED",
                        "value": "0x140038ae0",
                    },
                },
            },
            analysis_coverage={
                "mechanism_count": 28,
                "verified_mechanism_count": 1,
            },
        )
    )
    network = _chapter(official, "网络通信")
    thread = _chapter(official, "线程、TLS 回调与 APC")
    slots = _chapter(official, "十问槽位")
    assert "UNKNOWN(request)" in network
    assert "已过验证器门限" not in network
    network_slots = ""
    net_marker = "**网络通信"
    if net_marker in slots:
        network_slots = slots.split(net_marker, 1)[1]
        nxt = network_slots.find("\n**")
        if nxt >= 0:
            network_slots = network_slots[:nxt]
    assert "- Consumer: WinHttpSendRequest" not in network_slots
    assert "UNKNOWN(request)" in network_slots
    assert "已过验证器门限" not in thread
    # G5：fixture 的 how 已给出入口 `FUN_140038ae0@140038ae0`、output/consumer 也是该 VA，
    # 章必须报出已恢复的入口；旧断言要求写 UNKNOWN(start_routine) 固化的正是
    # Resume 3080 的漏报缺陷（库里 THREAD_CALLBACK 已 VERIFIED 且入口已恢复，报告却说未恢复）。
    assert "0x140038ae0" in thread
    assert "UNKNOWN(start_routine)" not in thread
    thread_slots = ""
    marker = "**线程、TLS 回调与 APC"
    if marker in slots:
        thread_slots = slots.split(marker, 1)[1]
        nxt = thread_slots.find("\n**")
        if nxt >= 0:
            thread_slots = thread_slots[:nxt]
    assert "0x140038ae0" not in thread_slots


def test_official_report_chrome_stamps_sample_name_and_ready_count() -> None:
    """C10: Report chrome must not say 未知样本 / Verified 0 when GET recovered both."""

    document = _v3_document(
        {
            "type": "pe",
            "path": "Resume.pdf.exe.VIR",
            "sha256": "6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145",
        },
        {
            "type": "behavior_finding",
            "catalog_id": "loader-and-api-resolution",
            "finding_status": "CANDIDATE",
            "target": "Resume.pdf.exe.VIR",
            "how": "GetProcAddress",
        },
        analysis_coverage={
            "mechanism_count": 28,
            "verified_mechanism_count": 1,
        },
    )
    stamped = stamp_official_report_chrome(document)
    assert stamped["sample_name"] == "Resume.pdf.exe.VIR"
    assert stamped["display_name"] == "Resume.pdf.exe.VIR"
    assert stamped["verified_mechanism_count"] == 1
    assert "未知样本" not in str(stamped["sample_name"])


def _process_gap_document() -> dict[str, object]:
    return {
        "analysis_coverage": {
            "mechanism_count": 2,
            "verified_mechanism_count": 0,
            "gaps": ["PROCESS_EXECUTION: creation_flags missing"],
        }
    }


def test_creation_flags_without_equals_is_not_reported_as_missing() -> None:
    """G0 §4.5：正文可能写成 `creation_flags0x00080000;`（没有 `=`）。

    页脚正则只认 `creation_flags\\s*=` 时匹配不到，就会套模板写
    `UNKNOWN(creation_flags)`，与正文自相矛盾。
    """
    from threat_report_agent.analyst_report import (
        _recovered_creation_flags,
        _verification_note,
    )

    rows: list[dict[str, object]] = [
        {"what": "CreateProcessW 调用点立即数 creation_flags0x00080000;"},
    ]
    assert _recovered_creation_flags(rows) == "0x00080000"
    note = "\n".join(_verification_note(_process_gap_document(), rows))
    assert "UNKNOWN(creation_flags)" not in note
    assert "已恢复" in note
    assert "0x00080000" in note


def test_all_creation_flags_spellings_are_recovered() -> None:
    """G0 §4.5：四种写法都要认：`=`、` = `、无分隔符、反引号包裹。"""
    from threat_report_agent.analyst_report import _recovered_creation_flags

    for blob in (
        "creation_flags=0x00080000",
        "creation_flags = 0x00080000",
        "creation_flags0x00080000;",
        "creation_flags `0x00080000`",
    ):
        assert _recovered_creation_flags([{"what": blob}]) == "0x00080000", blob


def test_implausible_immediate_is_not_a_recovered_creation_flag() -> None:
    """G0 §4.5：0x000f4240 更像超时常量，过不了 plausibility，不得当成已恢复 HOW。"""
    from threat_report_agent.analyst_report import _recovered_creation_flags

    assert _recovered_creation_flags([{"what": "creation_flags=0x000f4240;"}]) == ""
    assert _recovered_creation_flags([{"what": "creation_flags=0xffffffff;"}]) == ""


# --- G4 §8.3/§8.4: 报告合成门 (ADR-0036) -----------------------------------

_FRAGMENTS = (
    "## 分析结论\n\n"
    "### 网络通信\n\n"
    "已核对：网络通信。静态导入/字符串/调用序列与受控模拟均未提供对象级使用链。"
    "不是「样本没有恶意能力」的证明。\n\n"
    "### 进程创建\n\n"
    "CreateProcessW 调用；creation_flags 为 UNKNOWN(creation_flags)；状态 CANDIDATE（未过验证器）。\n"
)


def test_compose_gate_drops_a_draft_that_invents_an_endpoint() -> None:
    """G4 §8.4-2：润色稿加入片段没有的 URL → 官方正文不得出现它。"""
    from threat_report_agent.analyst_report import (
        compose_gate_violations,
        publish_composed_markdown,
    )

    draft = _FRAGMENTS + "\n样本回连 http://evil.example/gate.php。\n"
    assert compose_gate_violations(draft, _FRAGMENTS)
    published = publish_composed_markdown({}, draft, fragments=_FRAGMENTS)
    assert "evil.example" not in published
    # The fallback is still the complete report, not an empty one.
    assert "已核对：网络通信" in published


def test_compose_gate_rejects_upgrading_a_candidate() -> None:
    """G4 §8.4-3：润色把 CANDIDATE 写成已验证 → 门失败。"""
    from threat_report_agent.analyst_report import compose_gate_violations

    assert compose_gate_violations(_FRAGMENTS + "该进程创建机制已验证。", _FRAGMENTS)
    # A faithful restatement of the fragments passes.
    assert compose_gate_violations(_FRAGMENTS, _FRAGMENTS) == []


def test_compose_gate_rejects_another_samples_ioc() -> None:
    """G4 §8.3：把别的样本的任务名/IOC 写进来 → 门失败。"""
    from threat_report_agent.analyst_report import compose_gate_violations

    assert compose_gate_violations(_FRAGMENTS + "任务名为 resume.pdf。", _FRAGMENTS)
    assert compose_gate_violations(_FRAGMENTS + "子进程 FoxitPDFReader.exe。", _FRAGMENTS)


def test_compose_gate_rejects_invented_creation_flags() -> None:
    """G4 §8.3：片段里没有的 flags 值不得由润色补上。"""
    from threat_report_agent.analyst_report import compose_gate_violations

    assert compose_gate_violations(_FRAGMENTS + "\ncreation_flags=0x00080000。\n", _FRAGMENTS)


def test_unmatched_category_template_is_fixed_wording() -> None:
    """G4 §8.2-3：未命中说明必须同时说明核对过什么、缺哪个槽位、且不是排除证明。

    The wording is no longer a single frozen sentence: the project requires a specific blocker per
    category (`UNKNOWN(槽位)+具体卡点`) instead of one generic 套话, so this asserts the three
    obligations on the helper that produces it.
    """
    from threat_report_agent.analyst_report import AnalystTopic, unmatched_category_statement

    rendered = unmatched_category_statement(
        AnalystTopic(
            catalog_id="network-transport",
            title="网络通信",
            status="unmatched",
            reason="no anchors",
        )
    )
    assert rendered.startswith("未命中：网络通信。"), rendered
    assert "检索了" in rendered, rendered
    assert "UNKNOWN(" in rendered, rendered
    assert "不代表样本不具备该能力" in rendered, rendered
    # The generic 套话 the acceptance checker counts must not appear.
    assert "均未提供对象级使用链" not in rendered, rendered


def test_publish_without_a_draft_is_the_deterministic_report() -> None:
    """G4 §8.3-1：没有润色稿时发布确定性拼接稿，而不是退化成空文。"""
    from threat_report_agent.analyst_report import publish_composed_markdown

    published = publish_composed_markdown({}, "", fragments=_FRAGMENTS)
    assert published.strip() == _FRAGMENTS.strip()


def test_official_report_lists_every_applicable_category() -> None:
    """G4 §8.4-4：PE 主文含全部适用类目标题；未命中类目写固定已核对句。"""
    from threat_report_agent.analyst_report import unmatched_category_statement

    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32+",
                "machine": "0x8664",
                "entry_rva": "0x140001000",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "process-creation",
                "finding_status": "CANDIDATE",
                "what": "CreateProcessW",
                "how": "CreateProcessW 调用；creation_flags=0x00080000",
            },
        )
    )
    for title in (
        "编码、解密与配置还原",
        "网络通信",
        "进程创建",
        "父进程伪装（PPID）",
        "进程注入与隐蔽启动",
        "持久化",
        "线程、TLS 回调与 APC",
    ):
        assert f"### {title}" in official, title
    # An unmatched category must state what was looked for, name the missing slot as
    # `UNKNOWN(slot)`, and still refuse to treat absence as disproof. The previous fixed template
    # is now a counted 套话 (see `test_unmatched_category_blockers.py`), so this asserts the
    # CONTRACT rather than one frozen sentence.
    sentence = next(
        line for line in official.splitlines() if line.startswith("未命中：网络通信。")
    )
    assert "检索了" in sentence, sentence
    assert "UNKNOWN(" in sentence, sentence
    assert "不代表样本不具备该能力" in sentence, sentence


def test_non_pe_sample_does_not_get_windows_mandatory_chapters() -> None:
    """G4 §8.2-2：必写面只对 PE 适用；非 PE 不因模板而虚构 Windows 类目。"""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "behavior_finding",
                "catalog_id": "file-operations",
                "finding_status": "CANDIDATE",
                "what": "WriteFile",
                "how": "WriteFile 调用",
            },
        )
    )
    assert "### 父进程伪装（PPID）" not in official


def test_mechanism_closure_rate_lives_only_in_the_appendix() -> None:
    """G4 §8.4-5：主文可以没有「机制闭合率」；若出现只能在附录。

    十问槽、机制就绪计数、Seed Map 都是调查账本，不属于分析结论。
    """
    from threat_report_agent.analyst_report import split_analyst_markdown

    official = render_official_markdown(_dll_like_document())
    primary, appendix = split_analyst_markdown(official)
    assert primary.strip()
    assert appendix.strip()
    assert "机制闭合率" not in primary
    assert "机制闭合率" in appendix
    # 主文可以声明账本在别处（那是免责说明），但不得真的倾倒账本内容。
    assert "Investigation Seed Map" not in primary
    assert "FUN_1" not in primary


def _process_creation_document(flags: str) -> dict[str, object]:
    return _v3_document(
        {
            "type": "pe_basics",
            "format": "PE32+",
            "machine": "0x8664",
            "entry_rva": "0x140001000",
        },
        {
            "type": "behavior_finding",
            "catalog_id": "process-creation",
            "finding_status": "CANDIDATE",
            "what": "CreateProcessW command=`FoxitPDFReader.exe`",
            "how": (
                "CreateProcessW command=`FoxitPDFReader.exe`; "
                f"creation_flags={flags}; fallback=UNKNOWN(fallback)"
            ),
        },
        analysis_coverage={
            "mechanism_count": 4,
            "verified_mechanism_count": 0,
            "gaps": ["PROCESS_EXECUTION missing creation_flags"],
        },
    )


def test_process_creation_chapter_does_not_show_implausible_flags() -> None:
    """G5 §9.3 禁止项：正文不得把 0x000f4240 当已恢复的 creation_flags。

    0x000f4240 是 1,000,000 ms（WaitForSingleObject 超时），bit19 与
    EXTENDED_STARTUPINFO_PRESENT 撞位。页脚已用可信度门拒绝它；正文若仍展示该值，
    就会出现「正文有值、页脚 UNKNOWN」的自相矛盾——这正是计划 §3 根因表点名的
    「页脚撒谎」，也直接触犯 §2 禁令 #3。
    """
    from threat_report_agent.analyst_report import split_analyst_markdown

    official = render_official_markdown(_process_creation_document("0x000f4240"))
    primary, _appendix = split_analyst_markdown(official)
    assert "0x000f4240" not in primary
    assert "UNKNOWN(creation_flags)" in primary


def test_process_creation_chapter_shows_a_credible_flag_word() -> None:
    """正例对照：可信 flags 仍然要写进正文，不能被这次收紧误杀。"""
    from threat_report_agent.analyst_report import split_analyst_markdown

    official = render_official_markdown(_process_creation_document("0x00080000"))
    primary, _appendix = split_analyst_markdown(official)
    assert "0x00080000" in primary
    assert "已恢复" in primary


def test_verified_mechanism_projects_into_its_catalog_chapter() -> None:
    """G5：机制行带的是 mechanism_type（HTTP_DOWNLOAD），通常不带 catalog_id。

    只按 catalog_id 匹配会把已验证机制丢在章外，章内随即退回 UNKNOWN 模板——
    Resume 的 3080 报告就因此出现「网络通信写 UNKNOWN(request)，而库里
    HTTP_DOWNLOAD 是 VERIFIED 且 request 已恢复」的自相矛盾。
    """
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32+",
                "machine": "0x8664",
                "entry_rva": "0x140001000",
            },
            {
                "type": "mechanism_observation",
                "mechanism_type": "HTTP_DOWNLOAD",
                "status": "VERIFIED",
                "target": "Resume.pdf.exe.VIR",
                "inputs": ["http://198.51.100.7/payload.bin"],
                "transformation_or_control": [
                    "WinHttpOpen -> WinHttpOpenRequest -> WinHttpSendRequest"
                ],
                "outputs": ["response bytes"],
                "consumers": ["WinHttpSendRequest"],
                "evidence_ids": ["ev-http-1"],
            },
        )
    )
    chapter = _chapter(official, "网络通信")
    assert chapter, "网络通信 chapter missing"
    # 机制已 VERIFIED 且 endpoint 已恢复，章必须把它投影出来。
    assert "198.51.100.7" in chapter
    assert "未过验证器" not in chapter


def test_verified_thread_mechanism_does_not_fall_back_to_unknown_start_routine() -> None:
    """G5：THREAD_CALLBACK 已恢复 lpStartAddress 时，线程章不得退回 UNKNOWN(start_routine)。"""
    official = render_official_markdown(
        _v3_document(
            {
                "type": "pe_basics",
                "format": "PE32+",
                "machine": "0x8664",
                "entry_rva": "0x140001000",
            },
            {
                "type": "mechanism_observation",
                "mechanism_type": "THREAD_CALLBACK",
                "status": "VERIFIED",
                "target": "Resume.pdf.exe.VIR",
                "inputs": ["0x8"],
                "transformation_or_control": ["CreateThread lpStartAddress=0x140038ae0; lpParameter=0x8"],
                "outputs": ["0x140038ae0"],
                "consumers": ["0x140038ae0"],
                "evidence_ids": ["ev-thread-1"],
            },
        )
    )
    chapter = _chapter(official, "线程、TLS 回调与 APC")
    assert chapter, "thread chapter missing"
    # 入口 VA 已恢复，章必须写出来，而不是只说「这些不是已恢复的入口例程」。
    assert "0x140038ae0" in chapter
    assert "未过验证器" not in chapter


