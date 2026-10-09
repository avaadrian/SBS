# SBS console API (v0.3 contract)

The web console (`/`) and its JSON API are served by `sbs-server`. Agent endpoints
(`/api/v1/agent/*`) are separate and use the agent bearer token; they are described in
`internal/api/api.go`.

## Authentication

- `sbs-server -console-token <T>` (or env `SBS_CONSOLE_TOKEN`) turns on operator auth.
  Without it the console is open and the server logs a warning; it should then only be
  bound to localhost (the default `-addr 127.0.0.1:8080`). The server refuses to start
  with a non-loopback `-addr` and no console token, unless `-insecure-no-auth` is set.
- A request is authenticated when it carries either
  - the session cookie `sbs_session` (set by `POST /api/login`), or
  - `Authorization: Bearer <console token>` (for scripts and curl).
- The session cookie is `HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` when served over
  TLS, and holds an opaque random session ID (never the token itself). Sessions live in
  memory and expire after 12 hours.
- Unauthenticated requests to protected endpoints get `401 {"error":"login required"}`.
  `GET /` always serves the page; the page calls `GET /api/session` and shows a login form
  when needed.
- Every state-changing console request (POST/DELETE) also passes the existing CSRF guard:
  `Sec-Fetch-Site` must be same-origin/same-site/none, and requests with a body must be
  `Content-Type: application/json`.

## TLS

`-tls-cert <file> -tls-key <file>` serves HTTPS. Agents trust it via `server.ca_file` in the
agent config (or the system roots).

## Endpoints

All responses are JSON. Errors are `{"error": "<message>"}` with a 4xx/5xx status.

### Session
| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/session` | – | `{"auth_required": bool, "authenticated": bool, "ai": {"enabled": bool, "provider": "ollama/llama3.1"}}`. No auth needed. |
| POST | `/api/login` | `{"token": "..."}` | `204` + `Set-Cookie`; `401` on a bad token. Constant-time compare. Rate-limited (5 failures/min per client IP → `429`). |
| POST | `/api/logout` | – | `204`, clears the cookie and the session. |

### Overview and data (existing, now auth-protected)
| Method | Path | Notes |
|---|---|---|
| GET | `/api/overview` | Existing fields plus `"rules_version"` and `"ai"` (same shape as in `/api/session`). Each host additionally has `"desired_mode"` (operator override, `""` if none), `"rules_version"`, `"rules_error"`, and `"auto_response_tripped"` (all from its last heartbeat). |
| GET | `/api/hosts`, `/api/alerts`, `/api/alerts/{id}` | Unchanged shape. Hosts gain the fields above. |
| POST | `/api/alerts/{id}/triage`, `/approve`, `/decline` | Unchanged. |
| POST | `/api/hosts/{id}/commands` | Unchanged. |

### Live response mode
| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/api/hosts/{id}/mode` | `{"mode": "ask" \| "auto" \| "off" \| ""}` | `200 {"desired_mode": "..."}`. `""` clears the override (agent falls back to its config). Delivered to the agent in its next heartbeat response. The host's `response_mode` changes once the agent reports it. |

### Custom rules (distributed to agents)
A custom rule is one detection rule in the normal YAML format (one rule per entry),
stored by the server, validated with the real rule engine, and pushed to agents.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/rules` | – | `{"version": "...", "rules": [CustomRule...]}` newest first. |
| POST | `/api/rules` | `{"yaml": "- id: ...", "source": "manual" \| "ai"}` | `201 CustomRule`. `400 {"error"}` if the YAML is not exactly one valid rule, or its `id` collides with a built-in rule or another custom rule. New rules start **enabled**. |
| POST | `/api/rules/{id}/enabled` | `{"enabled": bool}` | `200 CustomRule` |
| DELETE | `/api/rules/{id}` | – | `204` |
| POST | `/api/rules/generate` | `{"description": "..."}` | `200 GeneratedRule` (see `internal/llm`); does **not** save. `503` when no AI analyst is configured. |

`CustomRule`:
```json
{"id": "cr_3f9a…", "rule_id": "CUSTOM-001", "title": "…", "severity": "high",
 "event": "process", "yaml": "- id: CUSTOM-001\n  …", "enabled": true,
 "source": "ai", "created_at": "2026-10-09T10:00:00Z"}
```

The rule set version is a hash of the enabled rules (stable for the same content); the
agent YAML served at `/api/v1/agent/rules` is the enabled rules concatenated as one YAML
list.

### AI incident summary
| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/api/hosts/{id}/incident` | – | `200 IncidentSummary` over that host's 50 most recent alerts; `404` unknown host; `400` no alerts; `503` no AI analyst. |

## Safety notes
- AI output stays advisory: generated rules are only saved when an operator posts them to
  `/api/rules`, and the UI shows the validated YAML for review before saving.
- Agents cap automatic responses with a circuit breaker (see the agent's
  `response.max_auto_actions_per_minute`), so a bad or malicious distributed rule cannot
  make an `auto`-mode agent kill processes en masse; when tripped the agent drops to `ask`
  and reports `auto_response_tripped`.
