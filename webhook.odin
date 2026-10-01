package linje

import "core:crypto"
import "core:crypto/hmac"
import "core:encoding/hex"
import "core:encoding/json"
import "core:fmt"
import "core:mem"
import "core:strconv"
import "core:strings"
import "core:time"

WEBHOOK_SCHEMA            :: "linje.outbound-event.v1"
WEBHOOK_MAX_BODY_BYTES    :: 1024 * 1024
WEBHOOK_MAX_CLOCK_SKEW_MS :: i64(5 * 60 * 1000)

Webhook_Headers :: struct {
	event_id:   string,
	message_id: string,
	project:    string,
	event_type: string,
	timestamp:  string,
	signature:  string,
}

Webhook_Options :: struct {
	secret:            string,
	project_id:        string,
	now_ms:            i64,
	max_clock_skew_ms: i64,
}

Webhook_Error_Kind :: enum {
	None,
	Configuration,
	Missing_Timestamp,
	Malformed_Timestamp,
	Stale_Timestamp,
	Future_Timestamp,
	Missing_Signature,
	Malformed_Signature,
	Invalid_Signature,
	Invalid_JSON,
	Invalid_Event,
}

Webhook_Error :: struct {
	kind:   Webhook_Error_Kind,
	reason: string,
}

webhook_error_status :: proc(error: Webhook_Error) -> int {
	switch error.kind {
	case .None:                    return 200
	case .Configuration:           return 0
	case .Missing_Timestamp,
	     .Malformed_Timestamp,
	     .Stale_Timestamp,
	     .Future_Timestamp,
	     .Missing_Signature,
	     .Malformed_Signature,
	     .Invalid_Signature:       return 401
	case .Invalid_JSON,
	     .Invalid_Event:           return 400
	}
	return 400
}

webhook_error_code :: proc(error: Webhook_Error) -> string {
	switch error.kind {
	case .None:                return ""
	case .Configuration:       return "configuration"
	case .Missing_Timestamp:   return "missing_timestamp"
	case .Malformed_Timestamp: return "malformed_timestamp"
	case .Stale_Timestamp:     return "stale_timestamp"
	case .Future_Timestamp:    return "future_timestamp"
	case .Missing_Signature:   return "missing_signature"
	case .Malformed_Signature: return "malformed_signature"
	case .Invalid_Signature:   return "invalid_signature"
	case .Invalid_JSON:        return "invalid_json"
	case .Invalid_Event:       return "invalid_event"
	}
	return "invalid_webhook"
}

Webhook_Message :: struct {
	id:            string,
	project:       string,
	status:        string,
	attempt_count: i64,
	last_error:    string,
	delivered_at:  string,
	updated_at:    string,
}

Webhook_Event :: struct {
	schema:         string,
	event_id:       string,
	event_type:     string,
	occurred_at_ms: i64,
	project:        string,
	message_id:     string,
	message:        Webhook_Message,
	allocator:      mem.Allocator,
}

delete_webhook_event :: proc(event: Webhook_Event) {
	delete(event.schema, event.allocator)
	delete(event.event_id, event.allocator)
	delete(event.event_type, event.allocator)
	delete(event.project, event.allocator)
	delete(event.message_id, event.allocator)
	delete(event.message.id, event.allocator)
	delete(event.message.project, event.allocator)
	delete(event.message.status, event.allocator)
	delete(event.message.last_error, event.allocator)
	delete(event.message.delivered_at, event.allocator)
	delete(event.message.updated_at, event.allocator)
}

webhook_event_type_valid :: proc(value: string) -> bool {
	return value == "message.accepted" || value == "message.delivered" ||
	       value == "message.bounced" || value == "message.dead"
}

webhook_status_for_event_type :: proc(value: string) -> string {
	switch value {
	case "message.accepted":  return "accepted"
	case "message.delivered": return "delivered"
	case "message.bounced":   return "bounced"
	case "message.dead":      return "dead"
	}
	return ""
}

webhook_hmac :: proc(secret, timestamp, body: string) -> [32]byte {
	ctx: hmac.Context
	digest: [32]byte
	hmac.init(&ctx, .SHA256, transmute([]byte)secret)
	hmac.update(&ctx, transmute([]byte)timestamp)
	hmac.update(&ctx, []byte{'.'})
	hmac.update(&ctx, transmute([]byte)body)
	hmac.final(&ctx, digest[:])
	return digest
}

webhook_signature_header :: proc(
	secret, timestamp, body: string,
	allocator := context.allocator,
) -> (string, bool) {
	digest := webhook_hmac(secret, timestamp, body)
	encoded, error := hex.encode(digest[:], allocator)
	if error != nil do return "", false
	result := fmt.aprintf("sha256=%s", string(encoded), allocator = allocator)
	delete(encoded, allocator)
	return result, result != ""
}

decode_webhook_signature :: proc(value: string, destination: ^[32]byte) -> bool {
	trimmed := strings.trim_space(value)
	if trimmed == "" do return false
	lower, error := strings.to_lower(trimmed, context.temp_allocator)
	if error != nil do return false
	hex_value := lower
	if strings.has_prefix(lower, "sha256=") do hex_value = lower[len("sha256="):]
	if len(hex_value) != 64 do return false
	decoded, ok := hex.decode_into_buffer(transmute([]byte)hex_value, destination[:])
	return ok && len(decoded) == len(destination[:])
}

canonical_uuid :: proc(value: string) -> bool {
	if len(value) != 36 do return false
	for character, index in transmute([]byte)value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' do return false
			continue
		}
		if !(('0' <= character && character <= '9') ||
		     ('a' <= character && character <= 'f')) {
			return false
		}
	}
	return true
}

json_object :: proc(value: json.Value) -> (json.Object, bool) {
	#partial switch object in value {
	case json.Object: return object, true
	}
	return nil, false
}

json_string :: proc(object: json.Object, key: string) -> (string, bool) {
	value, found := object[key]
	if !found do return "", false
	#partial switch text in value {
	case json.String: return string(text), true
	}
	return "", false
}

json_integer :: proc(object: json.Object, key: string) -> (i64, bool) {
	value, found := object[key]
	if !found do return 0, false
	#partial switch number in value {
	case json.Integer: return i64(number), true
	}
	return 0, false
}

clone_webhook_string :: proc(value: string, allocator: mem.Allocator) -> (string, bool) {
	copy, error := strings.clone(value, allocator)
	return copy, error == nil
}

invalid_event :: proc(reason: string) -> Webhook_Error {
	return {kind = .Invalid_Event, reason = reason}
}

verify_webhook :: proc(
	options: Webhook_Options,
	headers: Webhook_Headers,
	body: string,
	allocator := context.allocator,
) -> (event: Webhook_Event, verification_error: Webhook_Error) {
	secret := strings.trim_space(options.secret)
	project_id := strings.trim_space(options.project_id)
	if secret == "" do return {}, {kind = .Configuration, reason = "secret"}
	if project_id == "" do return {}, {kind = .Configuration, reason = "project-id"}

	if headers.timestamp == "" do return {}, {kind = .Missing_Timestamp}
	for character in transmute([]byte)headers.timestamp {
		if character < '0' || character > '9' do return {}, {kind = .Malformed_Timestamp}
	}
	timestamp, timestamp_ok := strconv.parse_i64(headers.timestamp)
	if !timestamp_ok do return {}, {kind = .Malformed_Timestamp}
	now_ms := options.now_ms
	if now_ms == 0 do now_ms = time.time_to_unix_nano(time.now()) / 1_000_000
	max_skew := options.max_clock_skew_ms
	if max_skew == 0 do max_skew = WEBHOOK_MAX_CLOCK_SKEW_MS
	if max_skew < 0 do return {}, {kind = .Configuration, reason = "max-clock-skew-ms"}
	if timestamp < now_ms && now_ms-timestamp > max_skew {
		return {}, {kind = .Stale_Timestamp}
	}
	if timestamp > now_ms && timestamp-now_ms > max_skew {
		return {}, {kind = .Future_Timestamp}
	}

	if headers.signature == "" do return {}, {kind = .Missing_Signature}
	supplied_signature: [32]byte
	if !decode_webhook_signature(headers.signature, &supplied_signature) {
		return {}, {kind = .Malformed_Signature}
	}
	expected_signature := webhook_hmac(secret, headers.timestamp, body)
	if crypto.compare_constant_time(expected_signature[:], supplied_signature[:]) != 1 {
		return {}, {kind = .Invalid_Signature}
	}

	root, parse_error := json.parse_string(body, .JSON, true, allocator)
	if parse_error != nil do return {}, {kind = .Invalid_JSON}
	defer json.destroy_value(root, allocator)
	object, object_ok := json_object(root)
	if !object_ok do return {}, invalid_event("not-an-object")

	schema, schema_ok := json_string(object, "schema")
	if !schema_ok || schema != WEBHOOK_SCHEMA do return {}, invalid_event("schema")
	event_id, event_id_ok := json_string(object, "event-id")
	if !event_id_ok || !canonical_uuid(event_id) do return {}, invalid_event("event-id")
	event_type, event_type_ok := json_string(object, "event-type")
	if !event_type_ok || !webhook_event_type_valid(event_type) {
		return {}, invalid_event("event-type")
	}
	message_id, message_id_ok := json_string(object, "message-id")
	message_id = strings.trim_space(message_id)
	if !message_id_ok || message_id == "" do return {}, invalid_event("message-id")
	occurred_at_ms, occurred_ok := json_integer(object, "occurred-at-ms")
	if !occurred_ok do return {}, invalid_event("occurred-at-ms")
	project, project_ok := json_string(object, "project")
	if !project_ok || strings.trim_space(project) == "" || project != project_id {
		return {}, invalid_event("project")
	}
	if event_id != headers.event_id do return {}, invalid_event("event-id-header")
	if message_id != headers.message_id do return {}, invalid_event("message-id-header")
	if project != headers.project do return {}, invalid_event("project-header")
	if event_type != headers.event_type do return {}, invalid_event("event-type-header")

	message_value, message_found := object["message"]
	if !message_found do return {}, invalid_event("message")
	message_object, message_ok := json_object(message_value)
	if !message_ok do return {}, invalid_event("message")
	nested_id, nested_id_ok := json_string(message_object, "id")
	if !nested_id_ok || nested_id != message_id do return {}, invalid_event("nested-message-id")
	nested_project, nested_project_ok := json_string(message_object, "project")
	if !nested_project_ok || nested_project != project do return {}, invalid_event("nested-project")
	status, status_ok := json_string(message_object, "status")
	if !status_ok || status != webhook_status_for_event_type(event_type) {
		return {}, invalid_event("nested-status")
	}

	event.allocator = allocator
	event.occurred_at_ms = occurred_at_ms
	event.schema, schema_ok = clone_webhook_string(schema, allocator)
	event.event_id, event_id_ok = clone_webhook_string(event_id, allocator)
	event.event_type, event_type_ok = clone_webhook_string(event_type, allocator)
	event.project, project_ok = clone_webhook_string(project, allocator)
	event.message_id, message_id_ok = clone_webhook_string(message_id, allocator)
	event.message.id, nested_id_ok = clone_webhook_string(nested_id, allocator)
	event.message.project, nested_project_ok = clone_webhook_string(nested_project, allocator)
	event.message.status, status_ok = clone_webhook_string(status, allocator)
	if !(schema_ok && event_id_ok && event_type_ok && project_ok && message_id_ok &&
	     nested_id_ok && nested_project_ok && status_ok) {
		delete_webhook_event(event)
		return {}, {kind = .Configuration, reason = "allocation"}
	}
	if attempt_count, ok := json_integer(message_object, "attempt-count"); ok {
		event.message.attempt_count = attempt_count
	}
	if last_error, ok := json_string(message_object, "last-error"); ok {
		cloned := false
		event.message.last_error, cloned = clone_webhook_string(last_error, allocator)
		if !cloned {
			delete_webhook_event(event)
			return {}, {kind = .Configuration, reason = "allocation"}
		}
	}
	if delivered_at, ok := json_string(message_object, "delivered-at"); ok {
		cloned := false
		event.message.delivered_at, cloned = clone_webhook_string(delivered_at, allocator)
		if !cloned {
			delete_webhook_event(event)
			return {}, {kind = .Configuration, reason = "allocation"}
		}
	}
	if updated_at, ok := json_string(message_object, "updated-at"); ok {
		cloned := false
		event.message.updated_at, cloned = clone_webhook_string(updated_at, allocator)
		if !cloned {
			delete_webhook_event(event)
			return {}, {kind = .Configuration, reason = "allocation"}
		}
	}
	return event, {}
}
