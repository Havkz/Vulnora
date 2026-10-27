# Direct CLI

`vulnora` opens the existing terminal UI. `vulnora run` uses the same
`ProjectSession`, scanner, project directory, checkpoints and evidence journal.
Only assess targets you own or are explicitly authorized to test.

```sh
vulnora run https://authorized.example --name "Website assessment" --intensity stealth
vulnora run --resume <project-uuid>
vulnora run https://authorized.example --provider codex --model codex-default --reasoning high
vulnora run https://authorized.example --provider claude --model sonnet --reasoning medium
vulnora run https://authorized.example --fallback-provider local --fallback-model installed-model:7b
vulnora run --help
```

Use an explicit HTTP(S) URL. Resume accepts a saved UUID and preserves its target
and intensity; it cannot be combined with a new URL, name or intensity. Projects
created in either interface are accessible from both. Provider/model overrides
apply to this process and do not modify saved settings or the installed CLI's
own configuration. `claude` selects the installed Claude Code CLI.

| Option | Behavior |
| --- | --- |
| `--name` | Name of a new project; defaults to the target hostname. |
| `--intensity auto\|stealth\|aggressive` | Existing scanning behavior and adaptive traffic policy. |
| `--provider`, `--model`, `--reasoning` | Inference selection; reasoning applies to Codex/Claude. |
| `--fallback-enabled true\|false` | Enable or disable fallback for this run. |
| `--fallback-provider`, `--fallback-model` | Override the alternative provider/model. |
| `--fallback-on-api-error`, `--fallback-on-rate-limit`, `--fallback-on-refusal` | Boolean overrides of the [central policy](FALLBACK.md); safety refusals never reroute. |
| `--verbose` | Expand process output using the existing transcript formatter. |
| `--resume` | Reopen a saved project without creating another one. |

The CLI prints the project UUID and resume command before starting. Graceful
interrupts cancel work, drain outstanding tasks and persist the checkpoint
before releasing the project lease and used local models. Forced termination
cannot guarantee cleanup; the next session uses existing checkpoint recovery.
Interrupted calls requiring review remain paused; inspect and approve recovery
through the TUI. A resumed completed project exports its saved report without
starting a new scan.

Reports are currently Markdown files in the shared projects directory. Exit
code `0` means the engine reported completed coverage (possibly with warnings),
`2` means paused or incomplete, and `1` means a command or persistence failure.
Handled SIGINT/SIGTERM use `130`/`143`. Completion does not prove the absence of
vulnerabilities.

## Provider checks and discovery

```sh
vulnora models --provider local
vulnora test --provider local --model installed-model:7b
vulnora test --provider codex
vulnora fallback
```

Local discovery queries the configured Ollama/OpenAI-compatible endpoint and
does not load weights or run inference. Other providers currently show the
built-in model catalogue. `test` performs one inference validation on the selected
provider only, with no fallback. A local model used by that test is released on
exit; Codex is not tested when `--provider local` is selected.

Configuration uses the same saved settings and `VULNORA_CONFIG_DIR` as the TUI.
Explicit scope/exclusion/rate overrides, a per-run config file, alternative
report formats and output-directory flags are still part of the ongoing
integration; they are not yet exposed by `run`.
