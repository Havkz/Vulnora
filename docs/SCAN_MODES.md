# Scan modes

Interactive projects apply their saved mode when opened. Change it from Settings
after pausing; the new mode is persisted with the complete scanner checkpoint.
Library callers can opt in with `scanningBehavior` on `VulnoraCommand`.

| Mode | Active operators | Concurrent HTTP requests per host | Minimum interval between starts | Initial timeout | Extra safe HTTP attempts |
| --- | ---: | ---: | ---: | ---: | ---: |
| Stealth | 1 | 1 | 1000 ms | 30 seconds | 0 |
| Auto | 3 | 2 | 250 ms | 15 seconds | 1 |
| Aggressive | 6 | 4 | 50 ms | 10 seconds | 2 |

The limits apply across operators sharing the Arsenal. Response bodies retain their
slot until completely received, with a 16 MiB per-response safety limit. A timeout
starts after admission and covers body reading. Existing target/operator/request
budgets remain enforced; a smaller configured operator pool or request timeout wins.
Each additional request is charged and checkpointed before sending. POST, PUT,
PATCH, DELETE, TRACE and requests carrying bodies never automatically replay.

These intentionally conservative starting points offer one request/second in
Stealth, four starts/second in Auto, and twenty starts/second in Aggressive before
adaptation. They are ceilings, not promises of completion rate. Waiting for a slow
body, the operator pool and existing budgets can lower throughput further.

429, 5xx, transport failures and unusually slow responses halve concurrency and
double pacing/backoff, up to four reductions. Base backoff is respectively 5, 2,
and 1 seconds. Pacing never exceeds 8 seconds; exponential backoff caps at 60
seconds, while a longer server Retry-After is honored. Timeouts adapt to four times
observed latency, capped at 60 seconds and the configured timeout ceiling. Eight
stable observations remove one reduction. Settings changes retain outstanding
server backoff, completed evidence, resource limits and consumed budgets.

The adjustment works without a model. AI task planning receives the enforced
limits and existing findings for prioritization; it cannot widen scope or increase
the ceilings. Stealth adds no identity randomization, traffic blending or monitoring
evasion. Dalfox's payload-bypass mode is explicitly disabled for these presets.

Native TCP probes and cancellable DNS queries use the same per-host scheduler.
Negative DNS answers are ordinary observations, not transport failures. Nmap has a
separate per-host port-scanning lane, so independent web checks can run alongside
it. Web scanners retain an exclusive lane to avoid interfering with other web
requests and timing measurements. Queued subprocesses do not consume their own
execution timeout before admission.
Nmap, Nuclei, ffuf, sqlmap, Gobuster, Feroxbuster, httpx, Katana, Naabu, Dalfox,
Nikto, dnsx, Subfinder, WhatWeb and curl receive their supported rate, worker,
delay, timeout and retry flags where available. Naabu's passes use retries + 1:
zero would restore its default. Nmap's deadline accounts for the final port count,
rate limit, probe delay and retries, with a finite cap. It does not combine
`--scan-delay` with the parallelism options Nmap ignores in that mode. Existing
subprocess deadlines and cancellation remain enforced.

External scanners control their own internal requests. Their native rate limits
and stop-on-error behavior apply during a run; Vulnora adjusts subsequent work
from completed results. Other command tools retain their own internal defaults
within the exclusive subprocess lane and existing timeout. Per-packet accounting,
live retuning inside an opaque subprocess and restarting its internal queues are
not claimed. Built-in HTTP retries are durably charged; external batch request
counts remain estimates when the tool cannot report measurements.

Flag references: [Nmap timing](https://nmap.org/book/man-performance.html),
[Nuclei CLI](https://docs.projectdiscovery.io/opensource/nuclei/running),
[ffuf rate and concurrency](https://github.com/ffuf/ffuf/wiki/Performance-and-rate).
