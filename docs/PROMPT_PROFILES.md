# Agent prompt profiles

VULNORA selects `small_model_30b` whenever the active provider or a configured
fallback is a local 30B/32B model. Other configurations use `large_model`.

## Token accounting

`small_model_30b` defaults to a total budget of 8,000 tokens per agent run. Set
`VULNORA_SMALL_MODEL_TOTAL_TOKEN_BUDGET` to override it (minimum 2,000, maximum
50,000).

The total is cumulative across every planning request and the final response. It
includes model input/prompt tokens and model output/response tokens. Tool output
is counted when it is placed into a subsequent model prompt. When a provider does
not report token usage, VULNORA conservatively estimates tokens from message,
tool-schema, and response character counts.

## Practical differences

`small_model_30b` exposes at most 12 relevant tools and 8 deduplicated findings,
with short evidence and source context. It permits at most 12 tool calls and stops
after two no-progress steps.

`large_model` exposes at most 20 relevant tools and 24 deduplicated findings. It
retains substantially more evidence and source context and asks for a concise
test-selection rationale. The rationale must add a decision, not repeat evidence.
