"""Deterministic test backends and OpenAI-compatible HTTP model clients."""

from __future__ import annotations

import json
import os
from collections import deque
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vulnweaver.common.hashing import stable_hash


class ModelMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: Literal["system", "user", "assistant", "tool"]
    content: str


class ModelUsage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)


class ModelResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str
    model: str
    usage: ModelUsage = Field(default_factory=ModelUsage)
    structured: dict[str, Any] | None = None
    request_hash: str


def request_hash(messages: Sequence[ModelMessage], response_schema: type[BaseModel] | None) -> str:
    return stable_hash(
        {
            "messages": [message.model_dump(mode="json") for message in messages],
            "response_schema": response_schema.model_json_schema() if response_schema else None,
        }
    )


def _validate_structured(
    content: str,
    response_schema: type[BaseModel] | None,
) -> dict[str, Any] | None:
    if response_schema is None:
        return None
    try:
        parsed = response_schema.model_validate_json(content)
    except (ValidationError, ValueError) as error:
        raise ValueError(f"model output failed schema validation: {error}") from error
    return parsed.model_dump(mode="json")


class FakeModelBackend:
    """Offline backend with a finite, explicit response queue."""

    def __init__(self, responses: Iterable[str] = (), *, model: str = "fake") -> None:
        self._responses = deque(responses)
        self.model = model

    def complete(
        self,
        messages: Sequence[ModelMessage],
        *,
        response_schema: type[BaseModel] | None = None,
    ) -> ModelResponse:
        if not self._responses:
            raise RuntimeError("FakeModelBackend response queue is exhausted")
        content = self._responses.popleft()
        return ModelResponse(
            content=content,
            model=self.model,
            structured=_validate_structured(content, response_schema),
            request_hash=request_hash(messages, response_schema),
        )


class ReplayModelBackend:
    """Replay responses captured as JSON Lines, keyed by canonical request hash."""

    def __init__(self, replay_file: Path) -> None:
        self._records: dict[str, ModelResponse] = {}
        with replay_file.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    record = ModelResponse.model_validate_json(line)
                except ValidationError as error:
                    raise ValueError(
                        f"invalid replay record on line {line_number}: {error}"
                    ) from error
                if record.request_hash in self._records:
                    raise ValueError(f"duplicate replay request hash on line {line_number}")
                self._records[record.request_hash] = record

    def complete(
        self,
        messages: Sequence[ModelMessage],
        *,
        response_schema: type[BaseModel] | None = None,
    ) -> ModelResponse:
        key = request_hash(messages, response_schema)
        try:
            record = self._records[key]
        except KeyError as error:
            raise KeyError(f"no replay response for request {key}") from error
        structured = _validate_structured(record.content, response_schema)
        return record.model_copy(update={"structured": structured})


class OpenAICompatibleBackend:
    """Minimal synchronous client for `/chat/completions` compatible servers."""

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key_env: str = "VW_MODEL_API_KEY",
        timeout_seconds: float = 120.0,
        temperature: float = 0.2,
        top_p: float = 0.95,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key_env = api_key_env
        self.timeout_seconds = timeout_seconds
        self.temperature = temperature
        self.top_p = top_p

    def complete(
        self,
        messages: Sequence[ModelMessage],
        *,
        response_schema: type[BaseModel] | None = None,
    ) -> ModelResponse:
        key = request_hash(messages, response_schema)
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [message.model_dump(mode="json") for message in messages],
            "temperature": self.temperature,
            "top_p": self.top_p,
        }
        if response_schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": response_schema.__name__,
                    "strict": True,
                    "schema": response_schema.model_json_schema(),
                },
            }
        headers = {"Content-Type": "application/json"}
        api_key = os.environ.get(self.api_key_env)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        with httpx.Client(timeout=self.timeout_seconds) as client:
            response = client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            body = response.json()

        try:
            content = body["choices"][0]["message"]["content"]
            usage = body.get("usage", {})
        except (KeyError, IndexError, TypeError) as error:
            raise ValueError("malformed OpenAI-compatible response") from error
        if not isinstance(content, str):
            raise ValueError("model response content must be text")
        return ModelResponse(
            content=content,
            model=str(body.get("model", self.model)),
            usage=ModelUsage(
                input_tokens=int(usage.get("prompt_tokens", 0)),
                output_tokens=int(usage.get("completion_tokens", 0)),
            ),
            structured=_validate_structured(content, response_schema),
            request_hash=key,
        )


class VLLMBackend(OpenAICompatibleBackend):
    """Named adapter for a local vLLM OpenAI-compatible server."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str = "http://127.0.0.1:8000/v1",
        timeout_seconds: float = 120.0,
        temperature: float = 0.2,
        top_p: float = 0.95,
    ) -> None:
        super().__init__(
            base_url=base_url,
            model=model,
            api_key_env="VW_VLLM_API_KEY",
            timeout_seconds=timeout_seconds,
            temperature=temperature,
            top_p=top_p,
        )


def write_replay_record(path: Path, response: ModelResponse) -> None:
    """Append one response without ever persisting request headers or API keys."""

    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(response.model_dump(mode="json"), sort_keys=True) + "\n")

