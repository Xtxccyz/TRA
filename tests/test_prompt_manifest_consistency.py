"""Every manifest entry must resolve to a file that exists, and be loadable by the product's own loader.

Why this exists: `prompts/manifest.json` registered `analyst-report-agent` ->
`analyst-report-system-v1.md` while that file was UNTRACKED, and `service.py` requires that prompt at report
time. A checkout without the file raises `PromptNotFound` at the moment a report is being written, i.e. the
failure surfaces far from its cause. The same class covered other referenced-but-untracked modules.

This test does not care about git tracking (the worktree is deliberately dirty and committing is out of
scope here). It pins the property that actually breaks a run: the manifest must resolve.
"""
from __future__ import annotations

import json
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent" / "prompts"
MANIFEST = PROMPTS_DIR / "manifest.json"


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_the_manifest_parses_and_declares_its_schema() -> None:
    data = _manifest()
    assert data.get("schema_version"), "the manifest lost its schema_version"
    assert isinstance(data.get("prompts"), list) and data["prompts"], "the manifest declares no prompts"


def test_every_manifest_entry_resolves_to_an_existing_file() -> None:
    missing: list[str] = []
    for entry in _manifest()["prompts"]:
        name = str(entry.get("file") or "")
        if not name or not (PROMPTS_DIR / name).is_file():
            missing.append(f"{entry.get('id')} -> {name!r}")
    assert not missing, (
        f"the manifest references prompt files that do not exist: {missing}. A run needing one of these "
        f"raises PromptNotFound while composing a report."
    )


def test_no_orphan_prompt_files_are_shipped() -> None:
    """The other direction: a file the manifest never names is dead weight or a forgotten entry."""
    declared = {str(entry.get("file") or "") for entry in _manifest()["prompts"]}
    present = {path.name for path in PROMPTS_DIR.glob("*.md")}
    orphans = sorted(present - declared)
    assert not orphans, f"prompt files exist that the manifest does not declare: {orphans}"


def test_ids_and_versions_are_unique() -> None:
    seen: set[tuple[str, str]] = set()
    duplicates: list[str] = []
    for entry in _manifest()["prompts"]:
        key = (str(entry.get("id") or ""), str(entry.get("version") or ""))
        if key in seen:
            duplicates.append(f"{key[0]}@{key[1]}")
        seen.add(key)
    assert not duplicates, f"duplicate manifest entries: {duplicates}"


def test_the_product_loader_can_require_every_entry() -> None:
    """Exercise the real loader, not just the JSON: this is what `service.py` calls at report time.

    The loader is `PromptRegistry.require` (a METHOD, not a module-level function - an earlier version of
    this test looked for a module-level callable, found none, and skipped, which would have left the exact
    path H2 breaks unverified). The test now fails loudly if the registry cannot be constructed.
    """
    from threat_report_agent.prompts import PromptRegistry

    registry = PromptRegistry.load_builtin()

    failures: list[str] = []
    for entry in _manifest()["prompts"]:
        try:
            definition = registry.require(str(entry["id"]), str(entry["version"]))
        except Exception as exc:  # noqa: BLE001 - the point is to report which entry fails and why
            failures.append(f"{entry['id']}@{entry['version']}: {type(exc).__name__}: {exc}")
            continue
        if not str(getattr(definition, "system_text", "") or "").strip():
            failures.append(f"{entry['id']}@{entry['version']}: resolved to empty system_text")
        if not str(getattr(definition, "sha256", "") or "").strip():
            failures.append(f"{entry['id']}@{entry['version']}: resolved without a sha256")
    assert not failures, f"the product's own loader cannot resolve manifest entries: {failures}"
