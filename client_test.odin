package linje

import "core:mem"
import "core:strings"
import "core:testing"

Fake_Transport :: struct {
	status:                 i64,
	body:                   string,
	retry_after:            string,
	transport_error:        Transport_Error,
	calls:                  int,
	request_url:            string,
	request_project_token:  string,
	request_body:           string,
	connect_timeout_ms:     i64,
	request_timeout_ms:     i64,
}

TEST_TO       := [1]string{"recipient@example.no"}
TEST_CC       := [1]string{"copy@example.no"}
TEST_REPLY_TO := [1]string{"reply@example.no"}

delete_fake_transport :: proc(fake: ^Fake_Transport) {
	delete(fake.request_url)
	delete(fake.request_project_token)
	delete(fake.request_body)
}

fake_transport :: proc(
	user_data: rawptr,
	request: ^Transport_Request,
	allocator: mem.Allocator,
) -> Transport_Response {
	fake := cast(^Fake_Transport)user_data
	fake.calls += 1
	delete(fake.request_url)
	delete(fake.request_project_token)
	delete(fake.request_body)
	fake.request_url, _ = clone(request.url, context.allocator)
	fake.request_project_token, _ = clone(request.project_token, context.allocator)
	fake.request_body, _ = clone(request.body, context.allocator)
	fake.connect_timeout_ms = request.connect_timeout_ms
	fake.request_timeout_ms = request.request_timeout_ms
	body, _ := clone(fake.body, allocator)
	retry_after, _ := clone(fake.retry_after, allocator)
	return {
		status      = fake.status,
		body        = body,
		retry_after = retry_after,
		error       = fake.transport_error,
	}
}

test_client :: proc(fake: ^Fake_Transport) -> (Client, Error) {
	return new_client({
		base_url       = "https://api.linje.test///",
		project_token  = " project-token ",
		transport      = fake_transport,
		transport_data = fake,
	})
}

test_message :: proc() -> Message {
	return {
		idempotency_key = "watch-alert:42",
		sender          = "sender@example.no",
		to              = TEST_TO[:],
		cc              = TEST_CC[:],
		reply_to        = TEST_REPLY_TO[:],
		subject         = "Bekreft \"nå\"",
		text            = "Første linje\nAndre linje",
		html            = "<p>Første & andre</p>",
	}
}

@(test)
client_configuration_is_explicit_and_validates_origin :: proc(t: ^testing.T) {
	fake: Fake_Transport
	client, error := test_client(&fake)
	defer delete_error(error)
	testing.expect_value(t, error.kind, Error_Kind.None)
	if error.kind == .None {
		defer delete_client(client)
		testing.expect_value(t, client.base_url, "https://api.linje.test")
		testing.expect_value(t, client.project_token, "project-token")
		testing.expect_value(t, client.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT_MS)
		testing.expect_value(t, client.request_timeout_ms, DEFAULT_REQUEST_TIMEOUT_MS)
	}

	loopback, loopback_error := new_client({
		base_url      = "http://127.0.0.1:6060/",
		project_token = "token",
		transport     = fake_transport,
	})
	defer delete_error(loopback_error)
	testing.expect_value(t, loopback_error.kind, Error_Kind.None)
	if loopback_error.kind == .None do delete_client(loopback)

	invalid_origins := []string{
		"",
		"http://api.linje.test",
		"ftp://api.linje.test",
		"https://user@api.linje.test",
		"https://api.linje.test/path",
		"https://api.linje.test?q=1",
		"https://api.linje.test/#fragment",
	}
	for origin in invalid_origins {
		invalid, invalid_error := new_client({
			base_url      = origin,
			project_token = "token",
			transport     = fake_transport,
		})
		defer delete_error(invalid_error)
		testing.expect_value(t, invalid_error.kind, Error_Kind.Configuration)
		if invalid_error.kind == .None do delete_client(invalid)
	}

	unsafe, unsafe_error := new_client({
		base_url      = "https://api.linje.test",
		project_token = "token\nInjected: yes",
		transport     = fake_transport,
	})
	defer delete_error(unsafe_error)
	testing.expect_value(t, unsafe_error.kind, Error_Kind.Configuration)
	if unsafe_error.kind == .None do delete_client(unsafe)
}

@(test)
submits_canonical_message_with_auth_json_and_timeouts :: proc(t: ^testing.T) {
	fake := Fake_Transport{
		status = 202,
		body   = `{"ok":true,"message-id":"msg-123"}`,
	}
	defer delete_fake_transport(&fake)
	client, client_error := new_client({
		base_url           = "https://api.linje.test",
		project_token      = "project-token",
		connect_timeout_ms = 321,
		request_timeout_ms = 654,
		transport          = fake_transport,
		transport_data     = &fake,
	})
	defer delete_error(client_error)
	testing.expect_value(t, client_error.kind, Error_Kind.None)
	if client_error.kind != .None do return
	defer delete_client(client)
	message := test_message()
	result, send_error := send_message(&client, &message)
	defer delete_error(send_error)
	testing.expect_value(t, send_error.kind, Error_Kind.None)
	if send_error.kind == .None {
		defer delete_send_result(result)
		testing.expect_value(t, result.message_id, "msg-123")
		testing.expect_value(t, result.http_status, i64(202))
	}
	testing.expect_value(t, fake.calls, 1)
	testing.expect_value(t, fake.request_url, "https://api.linje.test/v1/messages")
	testing.expect_value(t, fake.request_project_token, "project-token")
	testing.expect_value(t, fake.connect_timeout_ms, i64(321))
	testing.expect_value(t, fake.request_timeout_ms, i64(654))
	testing.expect(t, strings.contains(fake.request_body, `"idempotency-key":"watch-alert:42"`))
	testing.expect(t, strings.contains(fake.request_body, `"from":"sender@example.no"`))
	testing.expect(t, strings.contains(fake.request_body, `"to":["recipient@example.no"]`))
	testing.expect(t, strings.contains(fake.request_body, `"reply-to":["reply@example.no"]`))
	testing.expect(t, strings.contains(fake.request_body, `Bekreft \"nå\"`))
	testing.expect(t, strings.contains(fake.request_body, `Første linje\nAndre linje`))
}

@(test)
normalizes_http_failures_without_retrying :: proc(t: ^testing.T) {
	Case :: struct {
		status:    i64,
		kind:      Error_Kind,
		retryable: bool,
	}
	cases := []Case{
		{400, .Validation, false},
		{401, .Authentication, false},
		{403, .Authentication, false},
		{404, .Client_Error, false},
		{408, .Timeout, true},
		{409, .Validation, false},
		{425, .Transient, true},
		{429, .Rate_Limited, true},
		{500, .Server, true},
		{503, .Server, true},
	}
	for test_case in cases {
		fake := Fake_Transport{
			status      = test_case.status,
			body        = `{"ok":false,"error":"rejected","detail":"useful"}`,
			retry_after = "17",
		}
		client, client_error := test_client(&fake)
		testing.expect_value(t, client_error.kind, Error_Kind.None)
		if client_error.kind != .None {
			delete_error(client_error)
			continue
		}
		message := test_message()
		result, send_error := send_message(&client, &message)
		testing.expect_value(t, send_error.kind, test_case.kind)
		testing.expect_value(t, send_error.status, test_case.status)
		testing.expect_value(t, send_error.retryable, test_case.retryable)
		testing.expect_value(t, send_error.retry_after, "17")
		testing.expect_value(t, fake.calls, 1)
		if send_error.kind == .None do delete_send_result(result)
		delete_error(send_error)
		delete_client(client)
		delete_error(client_error)
		delete_fake_transport(&fake)
	}
}

@(test)
normalizes_transport_and_malformed_success_failures :: proc(t: ^testing.T) {
	transport_errors := []Transport_Error{
		Transport_Error.Timeout,
		Transport_Error.Network,
	}
	for transport_error in transport_errors {
		fake := Fake_Transport{transport_error = transport_error}
		client, client_error := test_client(&fake)
		defer delete_error(client_error)
		if client_error.kind != .None do continue
		defer delete_client(client)
		message := test_message()
		result, send_error := send_message(&client, &message)
		defer delete_error(send_error)
		expected := Error_Kind.Network
		if transport_error == .Timeout do expected = .Timeout
		testing.expect_value(t, send_error.kind, expected)
		testing.expect(t, send_error.retryable)
		testing.expect_value(t, fake.calls, 1)
		if send_error.kind == .None do delete_send_result(result)
		delete_fake_transport(&fake)
	}

	malformed_bodies := []string{
		"",
		"not json",
		"{}",
		`{"message-id":123}`,
		`{"message-id":"  "}`,
	}
	for body in malformed_bodies {
		fake := Fake_Transport{status = 202, body = body}
		client, client_error := test_client(&fake)
		defer delete_error(client_error)
		if client_error.kind != .None do continue
		defer delete_client(client)
		message := test_message()
		result, send_error := send_message(&client, &message)
		defer delete_error(send_error)
		testing.expect_value(t, send_error.kind, Error_Kind.Malformed_Response)
		if send_error.kind == .None do delete_send_result(result)
		delete_fake_transport(&fake)
	}
}

@(test)
rejects_invalid_message_before_transport :: proc(t: ^testing.T) {
	fake := Fake_Transport{status = 202, body = `{"message-id":"unused"}`}
	client, client_error := test_client(&fake)
	defer delete_error(client_error)
	if client_error.kind != .None do return
	defer delete_client(client)
	invalid := Message{sender = "sender@example.no", subject = "No recipients", text = "Text"}
	result, send_error := send_message(&client, &invalid)
	defer delete_error(send_error)
	testing.expect_value(t, send_error.kind, Error_Kind.Invalid_Message)
	testing.expect_value(t, fake.calls, 0)
	if send_error.kind == .None do delete_send_result(result)
}
