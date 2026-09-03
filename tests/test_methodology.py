from types import SimpleNamespace

from threat_report_agent.methodology import FactLibrary, build_profile


def _row(kind, module, value, evidence_id, anchor=None):
    return SimpleNamespace(
        id=evidence_id,
        kind=kind,
        module=module,
        value=value,
        anchor=anchor or {"type": "file_offset", "offset": 10},
    )


def test_profile_extracts_six_dimension_signals_and_preserves_evidence() -> None:
    observations = [
        _row("string", "static_triage", {"text": "WARRIORPRIDE", "encoding": "ascii"}, "e1"),
        _row("loader_indicator", "loader", {"indicator": "LoadLibraryW"}, "e2"),
        _row("crypto_indicator", "decryption", {"indicator": "RC4"}, "e3"),
        _row("network_indicator", "c2_network", {"indicator": "https://example.test/gate.php"}, "e4"),
        _row("anti_analysis_indicator", "anti_analysis", {"indicator": "IsDebuggerPresent"}, "e5"),
        _row("pe_structure", "static_triage", {"timestamp": 123, "sections": []}, "e6"),
    ]
    profile = build_profile(observations, name="sample.exe", fact_library=FactLibrary((), "test", "test"))

    assert set(profile.dimension_coverage) == {
        "loading_chain", "cryptography", "c2_design", "anti_analysis", "build_system", "codenames"
    }
    assert all(signal.evidence_ids for signal in profile.signals)
    assert profile.assessment.actual_verdict == "EXCLUDE_NSA"


def test_fact_matching_records_hit_and_context_mismatch() -> None:
    library = FactLibrary(
        facts=(
            {
                "id": "FACT-1",
                "pattern_type": "loader",
                "indicators": [{"type": "all", "value": "LoadLibraryW"}],
            },
        ),
        sha256="test",
        source="test",
    )
    profile = build_profile(
        [
            _row("loader_indicator", "loader", {"indicator": "LoadLibraryW"}, "e1"),
        ],
        name="sample.exe",
        fact_library=library,
    )
    assert profile.matches[0].fact_id == "FACT-1"
    assert profile.matches[0].status == "HIT"
    assert profile.matches[0].evidence_ids == ("e1",)
    assert profile.assessment.actual_verdict == "INCONCLUSIVE"

    mismatch_library = FactLibrary(
        facts=(
            {
                "id": "FACT-2",
                "pattern_type": "kernel-driver-loader",
                "purpose": "SMB kernel backdoor loading",
                "indicators": [{"type": "all", "value": "LoadLibraryW"}],
            },
        ),
        sha256="test-2",
        source="test",
    )
    mismatch_profile = build_profile(
        [_row("loader_indicator", "loader", {"indicator": "LoadLibraryW"}, "e2")],
        name="sample.exe",
        fact_library=mismatch_library,
    )
    assert mismatch_profile.matches[0].status == "MISMATCH"
    assert mismatch_profile.assessment.excluded_fact_ids == ("FACT-2",)


def test_profile_turns_pe_imports_and_call_sites_into_dimension_signals() -> None:
    profile = build_profile(
        [
            _row(
                "pe_structure",
                "static_triage",
                {
                    "imports": [
                        {
                            "module": "kernel32.dll",
                            "functions": [
                                "LoadLibraryA",
                                "GetProcAddress",
                                "VirtualProtect",
                                "CreateRemoteThread",
                                "WinHttpOpen",
                            ],
                        }
                    ],
                    "timestamp": 123,
                    "sections": [],
                },
                "pe-1",
            ),
            _row(
                "code_api_call",
                "static_triage",
                {"api": "BCryptDecrypt", "rva": 4096},
                "call-1",
                {"type": "rva_call_site", "rva": 4096},
            ),
        ],
        name="loader.dll",
        fact_library=FactLibrary((), "test", "test"),
    )

    assert profile.dimension_coverage["loading_chain"] >= 1
    assert profile.dimension_coverage["cryptography"] >= 1
    assert profile.dimension_coverage["c2_design"] >= 1
    assert any("VirtualProtect" in signal.value for signal in profile.signals)
    assert all(signal.evidence_ids for signal in profile.signals)


def test_profile_uses_catalog_values_only_when_present_in_observed_strings() -> None:
    library = FactLibrary(
        facts=(
            {
                "id": "FACT-CODENAME",
                "pattern_type": "internal-codename",
                "indicators": [{"type": "string", "value": "WZOWSKI"}],
            },
        ),
        sha256="catalog",
        source="test",
    )
    profile = build_profile(
        [_row("string", "static_triage", {"text": "prefix WZOWSKI suffix"}, "e-codename")],
        name="sample.dll",
        fact_library=library,
    )

    assert any(signal.dimension == "codenames" and signal.value == "WZOWSKI" for signal in profile.signals)
    assert any(match.fact_id == "FACT-CODENAME" and match.status == "HIT" for match in profile.matches)


def test_profile_does_not_treat_windows_paths_or_dll_names_as_c2() -> None:
    profile = build_profile(
        [
            _row("string", "static_triage", {"text": r"C:\\ApplicationData\\logFile.txt"}, "path-1"),
            _row("string", "static_triage", {"text": "KERNEL32.dll"}, "dll-1"),
        ],
        name="sample.exe",
        fact_library=FactLibrary((), "test", "test"),
    )

    assert profile.dimension_coverage["c2_design"] == 0


def test_short_numeric_observations_do_not_match_unrelated_catalog_indicators() -> None:
    library = FactLibrary(
        facts=(
            {
                "id": "FACT-LONG",
                "pattern_type": "loader",
                "indicators": [{"type": "constant", "value": "0x7A43E1FA"}],
            },
        ),
        sha256="catalog",
        source="test",
    )
    profile = build_profile(
        [_row("pe_structure", "static_triage", {"dll_characteristics": 0}, "e-zero")],
        name="sample.exe",
        fact_library=library,
    )

    assert profile.matches == ()
