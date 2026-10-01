package linje

import "core:fmt"
import "core:strings"
import "core:testing"

WEBHOOK_TEST_SECRET  :: "sekrit"
WEBHOOK_TEST_PROJECT :: "kraftradar"
WEBHOOK_TEST_NOW_MS  :: i64(1_700_000_000_000)

webhook_test_body :: proc(
	event_type := "message.delivered",
	message_id := "msg-1",
	project := WEBHOOK_TEST_PROJECT,
) -> string {
	status := webhook_status_for_event_type(event_type)
	return fmt.aprintf(
		`{{"schema":"linje.outbound-event.v1","event-id":"01234567-89ab-cdef-0123-456789abcdef","event-type":"%s","occurred-at-ms":1700000000000,"project":"%s","message-id":"%s","message":{{"id":"%s","project":"%s","status":"%s","attempt-count":1}}}}`,
		event_type,
		project,
		message_id,
		message_id,
		project,
		status,
	)
}

webhook_test_headers :: proc(body: string, timestamp := "1700000000000") -> Webhook_Headers {
	signature, ok := webhook_signature_header(WEBHOOK_TEST_SECRET, timestamp, body)
	assert(ok)
	return {
		event_id   = "01234567-89ab-cdef-0123-456789abcdef",
		message_id = "msg-1",
		project    = WEBHOOK_TEST_PROJECT,
		event_type = "message.delivered",
		timestamp  = timestamp,
		signature  = signature,
	}
}

webhook_test_options :: proc() -> Webhook_Options {
	return {
		secret     = WEBHOOK_TEST_SECRET,
		project_id = WEBHOOK_TEST_PROJECT,
		now_ms     = WEBHOOK_TEST_NOW_MS,
	}
}

@(test)
webhook_signature_matches_linje_contract_vector :: proc(t: ^testing.T) {
	signature, ok := webhook_signature_header(
		WEBHOOK_TEST_SECRET,
		"1700000000000",
		`{"schema":"linje.outbound-event.v1"}`,
	)
	defer delete(signature)
	testing.expect(t, ok)
	testing.expect_value(
		t,
		signature,
		"sha256=e3e72756dfda2d6825828c671ee2515088b2f20d1c6abb6053c81ff82a8e37ac",
	)
}

@(test)
webhook_accepts_valid_events_and_owns_result :: proc(t: ^testing.T) {
	event_types := [?]string{
		"message.accepted",
		"message.delivered",
		"message.bounced",
		"message.dead",
	}
	for event_type in event_types {
		body := webhook_test_body(event_type)
		defer delete(body)
		headers := webhook_test_headers(body)
		headers.event_type = event_type
		defer delete(headers.signature)
		event, verification_error := verify_webhook(webhook_test_options(), headers, body)
		defer delete_webhook_event(event)
		testing.expect_value(t, verification_error.kind, Webhook_Error_Kind.None)
		testing.expect_value(t, event.event_type, event_type)
		testing.expect_value(t, event.message_id, "msg-1")
		testing.expect_value(t, event.message.status, webhook_status_for_event_type(event_type))
		testing.expect_value(t, event.message.attempt_count, i64(1))
	}
}

@(test)
webhook_rejects_tampering_and_bad_freshness :: proc(t: ^testing.T) {
	body := webhook_test_body()
	defer delete(body)
	headers := webhook_test_headers(body)
	original_signature := headers.signature
	defer delete(original_signature)

	bad_signature := headers
	bad_signature.signature = "sha256=0000000000000000000000000000000000000000000000000000000000000000"
	_, signature_error := verify_webhook(webhook_test_options(), bad_signature, body)
	testing.expect_value(t, signature_error.kind, Webhook_Error_Kind.Invalid_Signature)

	stale_headers := webhook_test_headers(body, "1699999699999")
	defer delete(stale_headers.signature)
	_, stale_error := verify_webhook(webhook_test_options(), stale_headers, body)
	testing.expect_value(t, stale_error.kind, Webhook_Error_Kind.Stale_Timestamp)

	future_headers := webhook_test_headers(body, "1700000300001")
	defer delete(future_headers.signature)
	_, future_error := verify_webhook(webhook_test_options(), future_headers, body)
	testing.expect_value(t, future_error.kind, Webhook_Error_Kind.Future_Timestamp)
}

@(test)
webhook_requires_headers_to_match_envelope :: proc(t: ^testing.T) {
	body := webhook_test_body()
	defer delete(body)
	headers := webhook_test_headers(body)
	defer delete(headers.signature)
	headers.message_id = "other"
	_, verification_error := verify_webhook(webhook_test_options(), headers, body)
	testing.expect_value(t, verification_error.kind, Webhook_Error_Kind.Invalid_Event)
	testing.expect_value(t, verification_error.reason, "message-id-header")
}

@(test)
webhook_signature_accepts_bare_uppercase_hex :: proc(t: ^testing.T) {
	body := webhook_test_body()
	defer delete(body)
	headers := webhook_test_headers(body)
	original_signature := headers.signature
	defer delete(original_signature)
	bare_upper, error := strings.to_upper(headers.signature[len("sha256="):])
	testing.expect(t, error == nil)
	defer delete(bare_upper)
	headers.signature = bare_upper
	event, verification_error := verify_webhook(webhook_test_options(), headers, body)
	defer delete_webhook_event(event)
	testing.expect_value(t, verification_error.kind, Webhook_Error_Kind.None)
}
