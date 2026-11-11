import asyncio
import json
from copy import deepcopy
from typing import Any

import litellm
from litellm import ChatCompletionMessageToolCall, ModelResponse
from tool import Tool


def _prepare_tools(
    tools: list[Tool],
) -> tuple[list[dict[str, Any]], dict[str, Tool]]:
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


async def _run_tool(call: ChatCompletionMessageToolCall, handlers: dict[str, Tool]) -> dict[str, Any]:
    name = call.function.name
    try:
        tool = handlers[name]
        arguments = json.loads(call.function.arguments or "{}")
        if not isinstance(arguments, dict):
            raise TypeError("Tool arguments must be a JSON object")
        output = await tool.call(arguments)
        content = json.dumps(output, ensure_ascii=False, default=str)
    except Exception as exc:
        content = f"{type(exc).__name__}: {exc}"

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
        model: str | None,
        tools: list[dict[str, Any]] | None,
    ) -> list[dict[str, Any]]:
        """Fit a copy of the full context into the token budget.

        Remove oldest complete assistant/tool exchanges, preserving the
        initial prompt and newest assistant exchange. Never alter context.
        Override to implement a different reduction strategy.
        """
        messages = deepcopy(context)
        if max_input_tokens is None:
            return messages

        if model is None:
            return messages
        try:
            count = litellm.token_counter(model=model, messages=messages, tools=tools)
        except Exception:
            return messages  # Leave context-window enforcement to the provider.

        while count > max_input_tokens:
            fixed = 0
            while fixed < len(messages) and messages[fixed]["role"] in ("system", "developer"):
                fixed += 1
            if fixed < len(messages) and messages[fixed]["role"] == "user":
                fixed += 1  # Keep the initial user prompt.

            start = next(
                (i for i in range(fixed, len(messages)) if messages[i]["role"] == "assistant"),
                None,
            )
            if start is None:
                raise ValueError("Context exceeds max_input_tokens; cannot reduce further")
            end = start + 1
            while end < len(messages) and messages[end]["role"] == "tool":
                end += 1
            if not any(msg["role"] == "assistant" for msg in messages[end:]):
                raise ValueError("Context exceeds max_input_tokens; cannot reduce further")

            del messages[start:end]
            count = litellm.token_counter(model=model, messages=messages, tools=tools)

        return messages

    async def ask(
        self, context: list[dict[str, Any]] | None = None, **kwargs: Any
    ) -> tuple[ModelResponse, list[dict[str, Any]]]:
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

        # The full context is append-only; only the API-facing projection is reduced.
        while True:
            request_messages = await self.reduce(messages, max_input_tokens, model, tools)
            params["messages"] = request_messages

            # Only API calls hold a slot; Tool calls can recursively ask().
            async with self._semaphore:
                response = await litellm.acompletion(**params)
                if params.get("stream"):
                    chunks = [chunk async for chunk in response]
                    response = litellm.stream_chunk_builder(chunks, messages=request_messages)

            message = response.choices[0].message
            messages.append(message.model_dump(exclude_none=True))
            calls = getattr(message, "tool_calls", None)
            if not calls:
                return response, messages

            messages.extend(await asyncio.gather(*(_run_tool(call, handlers) for call in calls)))
