# Report V2 Contract

Report V2 is a projection of an immutable Analysis Snapshot. It selects 5-15
security findings from accepted Claims and verified Mechanisms, preserving
links to Evidence, ToolRuns, Artifacts, and ATT&CK mappings. It excludes raw
Evidence arrays, complete strings/imports/functions, and generic candidate
dumps from the main document.

Each critical finding answers WHAT, HOW, SECURITY MEANING, EVIDENCE, and
BOUNDARY. Unknown and negative conclusions remain explicitly calibrated. The
Anti-Bloat Gate rejects a main Markdown document over 40 KiB or a document
containing forbidden raw-dump markers. Evidence Explorer is the place for
bounded drill-down.
