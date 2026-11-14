# Scan execution and recovery

Vulnora continues an assessment while distinct, applicable checks remain. A successful check with no finding is useful evidence; a timeout or crash is not a negative security result.

| Rule | Location | Purpose |
| --- | --- | --- |
| No default cumulative token, iteration or tool-call ceiling | Agent loop and prompt profiles | Model size controls context and response size, not the amount of work permitted. Explicit caller limits remain available for bounded integrations. |
| Successful observations are shared and deduplicated | Agent loop and evidence orchestrator | Avoid repeating completed work; failed executions remain eligible for recovery. |
| Safe technical failures receive two retries after 1 and 2 seconds | Agent tool execution | Recover transient transport failures and terminated scanner processes. These intervals are Vulnora defaults, not a published standard. |
| Persistent technical failures pause with a saved checkpoint | Scheduler and project session | Never silently skip failed work or report it as complete. Ctrl+P retries eligible work. Writes and unknown interrupted operations still require inspection. |
| Nuclei uses a five-minute inactivity watchdog | Subprocess runner | Increasing request counts and real findings extend the watchdog. Unchanged periodic statistics do not. A progressing scan has no fixed overall five-minute cutoff. |
| Scope, authorization, rate limits and request budgets remain enforced | Tool orchestrator and scan policy | Keep execution within the selected assessment and preserve server backoff. |
| Completion reflects remaining coverage | Project journal and live view | Distinguish partial completion, warnings, blocked runs and successful completion. |

HTTP method checks use GET, HEAD, OPTIONS and TRACE. A 404 does not confirm method support. Advertised methods do not prove unauthorized access; write/delete probes are not performed by this check. A TRACE observation requires a successful response containing the reflected request, and does not establish exploitable impact by itself.

If an entire proposed batch reuses successful observations, the agent evaluates
those full results once without tools and hands remaining coverage back to the
scheduler. This does not apply to failed checks or distinct new observations.
Nmap port discovery and service detection are separate: service detection is
restricted to observed-open ports, and changing timing does not expand coverage.

Domain scope includes its subdomains; resolving that domain does not authorize raw
IP targets or redirects to them. A website hostname assessment checks HTTP/TLS
first and limits supporting Nmap checks to its web ports. Evidenced CDN/proxy
frontends make origin port scanning inapplicable; origin IPs require explicit
scope. HTTP proxy detection uses HTTP headers or technology evidence, rather than
DNS nameserver/registrar strings. Cloudflare documents that its [proxied addresses
are shared infrastructure](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/).

A negative Nuclei result does not replace targeted website validation. Impact
validation requires a confirmed candidate and authorization; if those prerequisites
are absent, its result remains explicitly inapplicable or blocked, never executed.

## Public surface discovery

`web_surface_review` reuses saved HTTP responses and reads observed links and
linked scripts within the target origin through the existing scope/rate/request
controls. HTML parsing uses [parse5](https://parse5.js.org/), including decoded
entities, relative/base URLs, form ownership and unquoted attributes. Form values
are not retained. GET parameter names from forms, links and OpenAPI documents
feed the existing XSS/SQLi recovery planner; POST forms are recorded but not submitted.

Script text is never evaluated. Literal `fetch(...)` and `axios` URL strings are
unverified API hints, not proof of endpoint reachability or the request method.
Browser-rendered routes and authenticated flows are not covered by this static
review. It does not turn script strings or HTML comments into real forms.

A review visits at most 32 distinct response candidates and parses at most
262,144 characters and 10,000 HTML nodes per response. Input/form/field inventories
are bounded to 128 entries. Common logout, deletion and credential-bearing links
are not automatically followed; these filters are not a guarantee that an arbitrary
GET endpoint has no side effects. Network failures and reached discovery/parsing
limits preserve partial evidence and mark the public-surface coverage incomplete,
rather than declaring inputs or authentication absent. Explicit risk and tool
exclusions still apply.

## Basis

- [Nuclei execution options](https://docs.projectdiscovery.io/opensource/nuclei/running) separate request timeouts, request retries, statistics and scan rate limits.
- [Nmap timing and performance](https://nmap.org/book/man-performance.html) explains adaptive timing and the loss of results caused by premature host timeouts.
- [HTTP semantics, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2) distinguishes safe automatic retry behavior from requests that can change server state.

The retry count, backoff intervals and inactivity window above are implementation choices. They are covered by local regression tests; they are not universal pentesting limits.
