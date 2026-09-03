from __future__ import annotations

import hashlib
import json
from importlib import resources

from pydantic import BaseModel, ConfigDict


class PromptDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: str
    sha256: str
    system_text: str


class PromptRegistry:
    def __init__(self, prompts: tuple[PromptDefinition, ...]) -> None:
        self._prompts = {(item.id, item.version): item for item in prompts}

    @classmethod
    def load_builtin(cls) -> "PromptRegistry":
        package = resources.files("threat_report_agent")
        manifest = json.loads(package.joinpath("prompts/manifest.json").read_text("utf-8"))
        prompts: list[PromptDefinition] = []
        for item in manifest["prompts"]:
            content = package.joinpath(f"prompts/{item['file']}").read_text("utf-8")
            prompts.append(
                PromptDefinition(
                    id=item["id"],
                    version=item["version"],
                    sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    system_text=content,
                )
            )
        return cls(tuple(prompts))

    def require(self, prompt_id: str, version: str) -> PromptDefinition:
        try:
            return self._prompts[(prompt_id, version)]
        except KeyError as exc:
            raise ValueError(f"Unknown prompt: {prompt_id}@{version}") from exc

    @staticmethod
    def build_messages(
        prompt: PromptDefinition,
        untrusted_context: dict[str, object],
    ) -> list[dict[str, str]]:
        serialized = json.dumps(
            untrusted_context,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        serialized = serialized.replace("<", "\\u003c").replace(">", "\\u003e")
        return [
            {"role": "system", "content": prompt.system_text},
            {
                "role": "user",
                "content": (
                    "<untrusted-analysis-data>\n" + serialized + "\n</untrusted-analysis-data>"
                ),
            },
        ]
