# Scanner reference

| Scanner | OWASP | Severity range | What it does |
|---------|-------|----------------|--------------|
| `sqli` | A03 | High–Critical | Error-based and time-based SQL injection probes |
| `xss` | A03 | Medium–High | Reflected, stored, and DOM-based XSS payloads |
| `ssrf` | A10 | High–Critical | Classic SSRF + cloud metadata endpoints (`pkg/scanner/dns_rebinding.go`) |
| `ssti` | A03 | Critical | Engine-fingerprinting SSTI (Jinja2 / Twig / FreeMarker / ERB / Spring EL) |
| `xxe` | A05 | Critical | XML external entity injection |
| `idor` | A01 | High | Insecure direct object reference enumeration |
| `path_traversal` | A01 | High | `../` and encoded variants |
| `command_injection` | A03 | Critical | Shell metacharacters with marker-based detection |
| `jwt` | A02 | High | alg=none, weak HS256 secret, kid traversal |
| `oauth` | A05 | Medium–High | OIDC discovery audit |
| `cors` / `cors_preflight` | A05 | Medium–High | Reflected origin, null origin, wildcard + credentials |
| `headers` | A05 | Low–Medium | HSTS, CSP, XFO, RP, PP, COOP, CORP, cookie flags |
| `secrets` | A02 | High | API key / token leakage in responses |
| `graphql` | A04 | High | Introspection enabled |
| `graphql_batching` | A04 | High | Batched / aliased rate-limit bypass |
| `nosql` | A03 | High | MongoDB operator injection |
| `ldap` | A03 | High | LDAP filter metachar injection |
| `xpath` | A03 | High | XPath operator injection |
| `prototype_pollution` | A08 | High | `__proto__` chain pollution in JSON APIs |
| `deserialization` | A08 | Critical | Java / PHP / Python / Ruby / .NET deserializer error leakage |
| `mass_assignment` | A08 | High | Privileged field acceptance |
| `race_condition` | A04 | Medium | Inconsistent status under concurrency |
| `smuggling` | A10 | High | HTTP request smuggling (CL.TE / TE.CL / TE.TE-obf) |
| `cache_poisoning` | A04 | High | Unkeyed header reflection |
| `cache_deception` | A04 | High | Dynamic content cached as static |
| `host_header` | A05 | High | Password-reset poisoning |
| `exposed_endpoints` | A05 | Info–Critical | `.git`, `.env`, `/actuator`, `/server-status`, … |
| `subdomain` | A05 | Info | Subdomain enumeration |
| `waf_detect` | — | Info | WAF fingerprint + bypass strategy selection |
| `vulnerable_components` | A06 | Variable | Dependency-version checks vs. CVE feed |
| `llm` | A05 | Variable | Prompt-injection probes against LLM-backed apps |
| `cloud-dockerfile` | A05 | Low–Critical | (offline) Dockerfile lint |
| `cloud-kubernetes` | A05 | Low–Critical | (offline) Pod / Deployment SecurityContext audit |
| `cloud-terraform` | A05 | Medium–High | (offline) Open security groups, public RDS, force_destroy |
| `cloud-dotenv` | A02 | High | (offline) Committed .env with real secrets |

## Disabling scanners

`temren scan --skip sqli,xxe --target https://...`

## Authoring a new scanner

See [CONTRIBUTING.md → Adding a new scanner](../CONTRIBUTING.md#adding-a-new-scanner).
