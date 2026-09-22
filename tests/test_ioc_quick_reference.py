"""The published body must give a labelled, compact pivot view - and must not omit the file's own hashes.

TWO MEASURED GAPS against the benchmark's 关键IOC速查.

1. **SHA1 and MD5 are missing from the body entirely.** Measured on task `50673002`:

       category            document   in published body
       sha256                 12          1      (correct: the resource digests are not file hashes)
       sha1                    1          0      <- the sample's own SHA1
       md5                     1          0      <- the sample's own MD5
       url / ipv4 / registry / scheduled_task / motw / process_name   all present

   `md5` is the identifier most commonly requested by an external party, and it was recorded in the
   document and rendered nowhere. This is R2: the fact exists, the body lacks it.

2. **No labelled pivot view.** The benchmark closes with a table (`C2 IP` / `C2 URL 1` / `C2 URL 2` /
   `任务名` / `XOR密钥表` / `编译语言` / `通信协议`). The published body contains the VALUES in prose and
   headings, so a reader must reconstruct the list; `probe-ioc-quickref.py` confirms no `IOC` /
   `速查` label exists in the body at all.

Both are fixed by one deterministic projection of the document's own `ioc` rows, which is also where the
file hashes get labelled as file identity rather than mixed in with object digests - the round-80/82
distinction, applied for the reader's benefit rather than only the rule's.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import render_official_markdown

SAMPLE_SHA256 = "6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145"
SAMPLE_SHA1 = "3928acc659677d5c7307c8e0d53e8b81b61f1127"
SAMPLE_MD5 = "be68ec2e1d56688ee411dd86e56b490c"
RESOURCE_SHA256 = "0b05c0df699028e6cfc4c02147e91b7a4ecbc79569004caaf550ebcdb25c63a3"


def _document(extra_iocs: list[dict] | None = None) -> dict:
    iocs = [
        {"type": "ioc", "category": "sha256", "value": SAMPLE_SHA256,
         "source": "static_triage/file_identity", "confidence": "HIGH"},
        {"type": "ioc", "category": "sha256", "value": RESOURCE_SHA256,
         "source": "investigation/embedded_object", "confidence": "HIGH"},
        {"type": "ioc", "category": "sha1", "value": SAMPLE_SHA1,
         "source": "static_triage/file_identity"},
        {"type": "ioc", "category": "md5", "value": SAMPLE_MD5,
         "source": "static_triage/file_identity"},
        {"type": "ioc", "category": "ipv4", "value": "69.48.228.74",
         "source": "static_triage/decode_result"},
        {"type": "ioc", "category": "url", "value": "http://69.48.228.74/ComHost.exe",
         "source": "static_triage/decode_result"},
        {"type": "ioc", "category": "scheduled_task",
         "value": "schtasks/create/tn/tr/sconce/st00:00/fschtasks",
         "source": "static_triage/string"},
        {"type": "ioc", "category": "motw", "value": "Zone.Identifier",
         "source": "static_triage/string"},
    ]
    return {
        "report_version": "3.0",
        "case_id": "case-ioc",
        "task_id": "task-ioc",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 1, "verified_mechanism_count": 0},
        "analyst_topics": [],
        "modules": [
            {"id": "static_triage", "title": "Static Triage", "summary": "",
             "rows": [*iocs, *(extra_iocs or [])]}
        ],
        "trace": {},
    }


def test_the_sample_hashes_reach_the_body() -> None:
    """MD5 and SHA1 were recorded and rendered nowhere; both are standard file identifiers."""
    body = render_official_markdown(_document())
    assert SAMPLE_SHA256 in body, "the sample SHA-256 is missing"
    assert SAMPLE_SHA1 in body, (
        "the sample's SHA-1 is in the document and absent from the published body"
    )
    assert SAMPLE_MD5 in body, (
        "the sample's MD5 is in the document and absent from the published body; MD5 is the identifier "
        "most often requested by an external party"
    )


def test_the_body_gives_a_labelled_pivot_view() -> None:
    """A reader must be able to copy the pivots without reconstructing them from prose."""
    body = render_official_markdown(_document())
    assert "IOC" in body, "the body has no IOC/pivot section, so the list must be reconstructed by hand"
    for label in ("文件 SHA-256", "文件 MD5", "IPv4", "URL"):
        assert label in body, f"the pivot view has no {label!r} label"


def test_a_resource_digest_is_not_labelled_as_the_sample_hash() -> None:
    """The round-80/82 provenance distinction must be visible to the reader, not only to the rule."""
    body = render_official_markdown(_document())
    section = body[body.find("IOC"):]
    # The resource digest may appear, but not under a file-identity label.
    if RESOURCE_SHA256 in section:
        index = section.find(RESOURCE_SHA256)
        context = section[max(0, index - 220): index + 220]
        assert "文件" not in context or "对象摘要" in context or "资源" in context, (
            "an object digest is listed under a file-hash label, so a reader would treat it as the "
            "sample's own hash"
        )


def test_the_pivot_view_is_bounded_and_says_so() -> None:
    """13 IOCs is fine; a run with hundreds must state the bound rather than print all of them."""
    many = [
        {"type": "ioc", "category": "url", "value": f"http://example.invalid/path/{index:04d}",
         "source": "static_triage/string"}
        for index in range(200)
    ]
    body = render_official_markdown(_document(many))
    assert body.count("example.invalid") < 200, (
        "every IOC was printed; a run with hundreds of pivots must be bounded"
    )
