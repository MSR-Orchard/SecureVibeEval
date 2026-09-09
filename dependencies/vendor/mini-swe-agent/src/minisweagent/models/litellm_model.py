import json
import logging
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

import litellm
from pydantic import BaseModel, Field

from minisweagent.exceptions import EmptyResponseError, FormatError
from minisweagent.models import GLOBAL_MODEL_STATS
from minisweagent.models.utils.actions_toolcall import (
    BASH_TOOL,
    format_toolcall_observation_messages,
    parse_toolcall_actions,
)
from minisweagent.models.utils.anthropic_utils import _reorder_anthropic_thinking_blocks
from minisweagent.models.utils.cache_control import set_cache_control
from minisweagent.models.utils.openai_multimodal import expand_multimodal_content
from minisweagent.models.utils.retry import retry

logger = logging.getLogger("litellm_model")


class LitellmModelConfig(BaseModel):
    model_name: str
    """Model name. Highly recommended to include the provider in the model name, e.g., `anthropic/claude-sonnet-4-5-20250929`."""
    model_kwargs: dict[str, Any] = {}
    """Additional arguments passed to the API."""
    litellm_model_registry: Path | str | None = os.getenv("LITELLM_MODEL_REGISTRY_PATH")
    """Model registry for cost tracking and model metadata. See the local model guide (https://mini-swe-agent.com/latest/models/local_models/) for more details."""
    set_cache_control: Literal["default_end"] | None = None
    """Set explicit cache control markers, for example for Anthropic models"""
    cost_tracking: Literal["default", "ignore_errors"] = os.getenv("MSWEA_COST_TRACKING", "default")
    """Cost tracking mode for this model. Can be "default" or "ignore_errors" (ignore errors/missing cost info)"""
    format_error_template: str = "{{ error }}"
    """Template used when the LM's output is not in the expected format."""
    observation_template: str = (
        "{% if output.exception_info %}<exception>{{output.exception_info}}</exception>\n{% endif %}"
        "<returncode>{{output.returncode}}</returncode>\n<output>\n{{output.output}}</output>"
    )
    """Template used to render the observation after executing an action."""
    multimodal_regex: str = ""
    """Regex to extract multimodal content. Empty string disables multimodal processing."""
    max_input_tokens: int = Field(default=0, ge=0)
    """Client-side input-history limit. Zero preserves the full conversation."""
    context_tokenizer_model: str = "gpt-4"
    """LiteLLM tokenizer used to estimate input length for unmapped local models."""
    context_trim_ratio: float = Field(default=0.9, gt=0, le=1)
    """Safety ratio applied to max_input_tokens before trimming."""


class LitellmModel:
    abort_exceptions: list[type[Exception]] = [
        litellm.exceptions.UnsupportedParamsError,
        litellm.exceptions.NotFoundError,
        litellm.exceptions.PermissionDeniedError,
        litellm.exceptions.ContextWindowExceededError,
        litellm.exceptions.AuthenticationError,
        KeyboardInterrupt,
    ]

    def __init__(self, *, config_class: Callable = LitellmModelConfig, **kwargs):
        self.config = config_class(**kwargs)
        if self.config.litellm_model_registry and Path(self.config.litellm_model_registry).is_file():
            litellm.utils.register_model(json.loads(Path(self.config.litellm_model_registry).read_text()))

    def _query(self, messages: list[dict[str, str]], **kwargs):
        try:
            return litellm.completion(
                model=self.config.model_name,
                messages=messages,
                tools=[BASH_TOOL],
                **(self.config.model_kwargs | kwargs),
            )
        except litellm.exceptions.AuthenticationError as e:
            e.message += " You can permanently set your API key with `mini-extra config set KEY VALUE`."
            raise e

    def _prepare_messages_for_api(self, messages: list[dict]) -> list[dict]:
        prepared = [{k: v for k, v in msg.items() if k != "extra"} for msg in messages]
        prepared = _reorder_anthropic_thinking_blocks(prepared)
        prepared = self._trim_messages_for_context(prepared)
        return set_cache_control(prepared, mode=self.config.set_cache_control)

    def _trim_messages_for_context(self, messages: list[dict]) -> list[dict]:
        """Keep the task plus the newest complete assistant/tool turns within the configured budget.

        LiteLLM's generic ``trim_messages`` can separate a tool response from the
        assistant tool call it answers and can discard the initial user task.  An
        agent trajectory needs both invariants, so trim only at complete-turn
        boundaries and always pin the leading system message(s) plus first task.
        """
        if self.config.max_input_tokens <= 0 or len(messages) <= 2:
            return messages

        tokenizer_model = self.config.context_tokenizer_model
        target_tokens = int(self.config.max_input_tokens * self.config.context_trim_ratio)

        def token_count(candidate: list[dict]) -> int:
            return litellm.token_counter(model=tokenizer_model, messages=candidate)

        try:
            original_tokens = token_count(messages)
        except Exception:
            logger.exception("Unable to estimate input tokens; preserving the complete conversation")
            return messages
        if original_tokens <= target_tokens:
            return messages

        # Pin every leading system message and the first non-system message,
        # which is the rendered task in mini-SWE-agent trajectories.
        pinned_end = 0
        for index, message in enumerate(messages):
            pinned_end = index + 1
            if message.get("role") != "system":
                break
        pinned = messages[:pinned_end]

        # Group each assistant tool call with all immediately following tool
        # results. Other messages form one-message units. Trimming whole units
        # keeps OpenAI-compatible tool_call_id relationships valid.
        units: list[list[dict]] = []
        index = pinned_end
        while index < len(messages):
            unit = [messages[index]]
            index += 1
            if unit[0].get("role") == "assistant":
                while index < len(messages) and messages[index].get("role") == "tool":
                    unit.append(messages[index])
                    index += 1
            units.append(unit)

        marker = {
            "role": "user",
            "content": (
                "<context_note>Older interaction turns were omitted to keep the "
                "agent conversation within the configured input-token limit. "
                "The original task and the most recent complete tool-call turns are preserved.</context_note>"
            ),
        }
        kept_units: list[list[dict]] = []
        for unit in reversed(units):
            candidate_units = [unit, *kept_units]
            candidate = pinned + [marker] + [message for group in candidate_units for message in group]
            try:
                if token_count(candidate) > target_tokens:
                    break
            except Exception:
                logger.exception("Unable to estimate trimmed input tokens; preserving the complete conversation")
                return messages
            kept_units = candidate_units

        trimmed = pinned + [marker] + [message for unit in kept_units for message in unit]
        try:
            trimmed_tokens = token_count(trimmed)
        except Exception:
            logger.exception("Unable to verify trimmed input tokens; preserving the complete conversation")
            return messages
        if trimmed_tokens > target_tokens:
            logger.warning(
                "Pinned task exceeds the configured context budget (%d > %d); preserving the complete conversation",
                trimmed_tokens,
                target_tokens,
            )
            return messages
        logger.info(
            "Trimmed agent input history from %d to %d estimated tokens and from %d to %d messages",
            original_tokens,
            trimmed_tokens,
            len(messages),
            len(trimmed),
        )
        return trimmed

    def query(self, messages: list[dict[str, str]], **kwargs) -> dict:
        for attempt in retry(logger=logger, abort_exceptions=self.abort_exceptions):
            with attempt:
                response = self._query(self._prepare_messages_for_api(messages), **kwargs)
                # Some upstreams (e.g. GitHub Copilot) intermittently return a 200 with an
                # empty `choices` list (transient backend hiccup / filtered completion). That
                # is not a successful response: downstream parsing does `choices[0]` and would
                # crash the whole instance. Raise inside the retry block so it is retried
                # instead. The exception type is not in `abort_exceptions`, so tenacity retries.
                if not getattr(response, "choices", None):
                    raise EmptyResponseError(
                        f"Model {self.config.model_name!r} returned a response with no choices; retrying."
                    )
        cost_output = self._calculate_cost(response)
        GLOBAL_MODEL_STATS.add(cost_output["cost"])
        # Note: all model.query() implementations must persist the response on FormatError.
        try:
            actions = self._parse_actions(response)
        except FormatError as e:
            try:
                e.messages[0]["extra"]["response"] = response.model_dump(mode="json")
            except Exception:
                # model_dump failed (e.g. unserializable object); fall back to repr
                # so the spec contract ("response MUST be persisted") holds unconditionally.
                e.messages[0]["extra"]["response"] = repr(response)
            raise
        message = response.choices[0].message.model_dump()
        message["extra"] = {
            "actions": actions,
            "response": response.model_dump(),
            **cost_output,
            "timestamp": time.time(),
        }
        return message

    def _calculate_cost(self, response) -> dict[str, float]:
        try:
            cost = litellm.cost_calculator.completion_cost(response, model=self.config.model_name)
            if cost <= 0.0:
                raise ValueError(f"Cost must be > 0.0, got {cost}")
        except Exception as e:
            cost = 0.0
            if self.config.cost_tracking != "ignore_errors":
                msg = (
                    f"Error calculating cost for model {self.config.model_name}: {e}, perhaps it's not registered? "
                    "You can ignore this issue from your config file with cost_tracking: 'ignore_errors' or "
                    "globally with export MSWEA_COST_TRACKING='ignore_errors'. "
                    "Alternatively check the 'Cost tracking' section in the documentation at "
                    "https://klieret.short.gy/mini-local-models. "
                    " Still stuck? Please open a github issue at https://github.com/SWE-agent/mini-swe-agent/issues/new/choose!"
                )
                logger.critical(msg)
                raise RuntimeError(msg) from e
        return {"cost": cost}

    def _parse_actions(self, response) -> list[dict]:
        """Parse tool calls from the response. Raises FormatError if unknown tool."""
        tool_calls = response.choices[0].message.tool_calls or []
        return parse_toolcall_actions(tool_calls, format_error_template=self.config.format_error_template)

    def format_message(self, **kwargs) -> dict:
        return expand_multimodal_content(kwargs, pattern=self.config.multimodal_regex)

    def format_observation_messages(
        self, message: dict, outputs: list[dict], template_vars: dict | None = None
    ) -> list[dict]:
        """Format execution outputs into tool result messages."""
        actions = message.get("extra", {}).get("actions", [])
        return format_toolcall_observation_messages(
            actions=actions,
            outputs=outputs,
            observation_template=self.config.observation_template,
            template_vars=template_vars,
            multimodal_regex=self.config.multimodal_regex,
        )

    def get_template_vars(self, **kwargs) -> dict[str, Any]:
        return self.config.model_dump()

    def serialize(self) -> dict:
        return {
            "info": {
                "config": {
                    "model": self.config.model_dump(mode="json"),
                    "model_type": f"{self.__class__.__module__}.{self.__class__.__name__}",
                },
            }
        }
