import asyncio
import json
import logging
from collections.abc import Callable
from copy import deepcopy
from functools import partial
from itertools import count
from typing import Any
from uuid import uuid4

import litellm
from litellm import ChatCompletionMessageToolCall

from .tools.tool import Tool

logger = logging.getLogger(__name__)


def _prepare_tools(tools: list[Tool]) -> tuple[list[dict[str, Any]], dict[str, Tool]]:
    definitions = []
    handlers = {}
    for tool in tools:
        definition = tool.description
        name = definition["function"]["name"]
        if name in handlers:
            raise ValueError(f"Duplicate tool name: {name}")
        definitions.append(definition)
        handlers[name] = tool
    return definitions, handlers


async def _run_tool(call: ChatCompletionMessageToolCall, handlers: dict[str, Tool], run_id: str) -> dict[str, Any]:
    name = call.function.name
    logger.info(
        "tool_call",
        extra={
            "run_id": run_id,
            "data": {
                "id": call.id,
                "name": name,
                "arguments": call.function.arguments,
            },
        },
    )
    try:
        tool = handlers[name]
        arguments = json.loads(call.function.arguments or "{}")
        if not isinstance(arguments, dict):
            raise TypeError("Tool arguments must be a JSON object")
        output = await tool.call(arguments)
        content = json.dumps(output, ensure_ascii=False, default=str)
    except Exception as exc:
        content = f"{type(exc).__name__}: {exc}"

    logger.info(
        "tool_result",
        extra={
            "run_id": run_id,
            "data": {
                "id": call.id,
                "name": name,
                "content": content,
            },
        },
    )
    return {"role": "tool", "tool_call_id": call.id, "name": name, "content": content}


class Runtime:
    """Async tool loop with at most `n` simultaneous LiteLLM API calls.

    Constructor keywords act as defaults for ask(). `max_input_tokens` is a
    local context limit; all other keywords are passed to litellm.acompletion().
    `context` is a list of conversation messages, including tool calls/results.
    """

    def __init__(self, n: int, **kwargs: Any) -> None:
        if type(n) is not int or n < 1:
            raise ValueError("n must be a positive integer")
        self._semaphore = asyncio.Semaphore(n)
        self._defaults = kwargs.copy()

    async def reduce(
        self,
        context: list[dict[str, Any]],
        max_input_tokens: int | None,
        token_counter: Callable[..., int] | None,
    ) -> list[dict[str, Any]]:
        """Limit tool output size, then discard oldest exchanges to fit the budget.

        Keep the initial prompt and leave the original context unchanged.
        Override to implement a different reduction strategy.
        """
        messages = deepcopy(context)
        limit = 64 * 1024
        marker = "\n[Tool output truncated]"
        marker_size = len(marker.encode("utf-8"))
        for message in messages:
            if message["role"] != "tool" or not isinstance(message.get("content"), str):
                continue
            content = message["content"].encode("utf-8")
            if len(content) > limit:
                message["content"] = content[: limit - marker_size].decode("utf-8", errors="ignore") + marker

        if max_input_tokens is None or token_counter is None:
            return messages
        try:
            count = token_counter(messages=messages)
        except Exception:
            return messages  # Leave context-window enforcement to the provider.

        fixed = 0
        while fixed < len(messages) and messages[fixed]["role"] in ("system", "developer"):
            fixed += 1
        if fixed < len(messages) and messages[fixed]["role"] == "user":
            fixed += 1  # Keep the initial user prompt.

        while count > max_input_tokens:
            if fixed == len(messages):
                raise ValueError("Context exceeds max_input_tokens; cannot reduce further")
            end = fixed + 1
            if messages[fixed]["role"] == "assistant":
                while end < len(messages) and messages[end]["role"] == "tool":
                    end += 1
            del messages[fixed:end]
            count = token_counter(messages=messages)

        return messages

    async def ask(self, context: list[dict[str, Any]] | None = None, **kwargs: Any) -> list[dict[str, Any]]:
        run_id = uuid4().hex
        try:
            params = {**self._defaults, **kwargs}
            max_input_tokens = params.pop("max_input_tokens", None)
            if max_input_tokens is not None and (type(max_input_tokens) is not int or max_input_tokens <= 0):
                raise ValueError("max_input_tokens must be positive")
            model = params.get("model")
            if max_input_tokens is None and model:
                try:
                    max_input_tokens = litellm.get_model_info(model)["max_input_tokens"]
                except Exception:
                    pass  # Unknown OpenAI-compatible models may lack metadata.

            if context is None:
                messages = deepcopy(params.get("messages") or [])
            else:
                messages = deepcopy(context)
                # Default messages are initial messages, not appended on every continuation.
                messages.extend(deepcopy(kwargs.get("messages") or []))
            params["messages"] = messages

            tools = params.get("tools")
            handlers = {}
            if tools is not None:
                tools, handlers = _prepare_tools(tools)
                params["tools"] = tools

            if not params.get("tools"):
                params.pop("tools", None)

            logger.info(
                "run_start",
                extra={
                    "run_id": run_id,
                    "data": {
                        "model": model,
                        "messages": messages,
                        "tools": tools,
                    },
                },
            )

            token_counter = partial(litellm.token_counter, model=model, tools=tools) if model else None

            # The full context is append-only; only the API-facing projection is reduced.
            for round in count(1):
                request_messages = await self.reduce(messages, max_input_tokens, token_counter)
                params["messages"] = request_messages
                logger.info(
                    "llm_request",
                    extra={
                        "run_id": run_id,
                        "data": {
                            "round": round,
                            "message_count": len(request_messages),
                            "model": model,
                        },
                    },
                )

                # Only API calls hold a slot; Tool calls can recursively ask().
                async with self._semaphore:
                    response = await litellm.acompletion(**params)
                    if params.get("stream"):
                        chunks = [chunk async for chunk in response]
                        response = litellm.stream_chunk_builder(chunks, messages=request_messages)

                logger.info(
                    "llm_response",
                    extra={
                        "run_id": run_id,
                        "data": {
                            "round": round,
                            "response": response.model_dump(exclude_none=True),
                        },
                    },
                )
                message = response.choices[0].message
                messages.append(message.model_dump(exclude_none=True))
                calls = message.tool_calls
                if not calls:
                    logger.info(
                        "run_end",
                        extra={
                            "run_id": run_id,
                            "data": {
                                "output": message.content,
                                "message_count": len(messages),
                            },
                        },
                    )
                    return messages

                messages.extend(await asyncio.gather(*(_run_tool(call, handlers, run_id) for call in calls)))
        except BaseException as exc:
            logger.error(
                "run_error",
                extra={
                    "run_id": run_id,
                    "data": {
                        "error": str(exc),
                        "type": type(exc).__name__,
                    },
                },
            )
            raise
