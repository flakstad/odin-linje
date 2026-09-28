# Odin Linje

Typed Odin client for Linje's public message submission API. The package owns
the HTTP boundary and stable failure classification; applications own message
content, durable outboxes, retry scheduling, delivery-state persistence, and
business handling.

```odin
import linje "deps/linje"

client, client_error := linje.new_client({
	base_url      = "https://api.linje.systems",
	project_token = project_token,
})
defer linje.delete_error(client_error)
if client_error.kind != .None {
	// configuration failure
	return
}
defer linje.delete_client(client)

recipients := [1]string{"customer@example.net"}
message := linje.Message{
	idempotency_key = "order:82921:shipped",
	sender          = "orders@example.no",
	to              = recipients[:],
	subject         = "Order shipped",
	text            = "Your order has shipped.",
}
result, send_error := linje.send_message(&client, &message)
defer linje.delete_error(send_error)
if send_error.kind == .None {
	defer linje.delete_send_result(result)
	// result.message_id is the stable Linje message ID.
}
```

The default transport uses libcurl with TLS verification, no redirects, a
5-second connect timeout, and a 15-second total request timeout. Tests and
specialized consumers may inject a `Transport_Proc`; the client never retries
implicitly.

Run the tests with:

```sh
odin test . -vet -strict-style
```

## Ownership

`new_client`, `send_message`, and failures return owned strings using the
provided allocator. Match successful values with:

- `delete_client`
- `delete_send_result`
- `delete_error`

`Message` and its recipient slices are borrowed for the duration of
`send_message`. A transport response is owned by the client call and released
after it has been interpreted.

## Security boundary

Only HTTPS origins are accepted, except loopback HTTP for local tests. Origins
with paths, user information, queries, or fragments are rejected. Project
tokens containing NUL, CR, or LF are rejected before transport. Redirects are
disabled, TLS peer and hostname verification are enabled, and response bodies
are bounded to 2 MiB.

See [DESIGN.md](DESIGN.md) for the wire contract and error vocabulary.
