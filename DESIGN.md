# Design

## Scope

The package submits canonical messages to `POST /v1/messages` with
`Authorization: Bearer <project token>`, JSON request and response bodies, and
no automatic retry. A project-scoped idempotency key is a JSON body field, not
an HTTP header.

Required message values are a sender, at least one recipient across `to`, `cc`,
and `bcc`, a subject, and either text or HTML content. Optional fields are the
idempotency key, `cc`, `bcc`, `reply-to`, text, and HTML.

A successful response is any 2xx response containing a nonblank string
`message-id`. The result preserves that ID, the HTTP status, and the raw JSON
response body.

## Errors

Failures are normalized as:

| Condition | Kind | Retryable |
| --- | --- | --- |
| Invalid options | `Configuration` | no |
| Invalid message | `Invalid_Message` | no |
| Transport timeout or HTTP 408 | `Timeout` | yes |
| Other transport failure | `Network` | yes |
| HTTP 401/403 | `Authentication` | no |
| HTTP 425 | `Transient` | yes |
| HTTP 429 | `Rate_Limited` | yes |
| HTTP 5xx | `Server` | yes |
| HTTP 400/409/422 | `Validation` | no |
| Other HTTP 4xx | `Client_Error` | no |
| Other non-2xx | `HTTP_Error` | no |
| Invalid success JSON or message ID | `Malformed_Response` | no |

The client exposes `retry_after` when supplied by the transport and keeps at
most 2,000 bytes of a failed response as diagnostic context. Applications make
retry decisions; the package performs exactly one request per call.

## Transport seam

`Transport_Proc` receives the validated URL, project token, encoded body, and
timeouts. It returns an owned body, optional Retry-After value, status, and a
transport error. This keeps protocol tests deterministic while the default
libcurl implementation exercises the same interface.

Outbound lifecycle webhook verification is intentionally not part of version
0.1. It will be added as a separate API without widening or changing the
message-submission contract.
