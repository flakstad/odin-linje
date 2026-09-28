package linje

import "core:encoding/json"
import "core:fmt"
import "core:mem"
import "core:strings"

DEFAULT_CONNECT_TIMEOUT_MS :: i64(5_000)
DEFAULT_REQUEST_TIMEOUT_MS :: i64(15_000)
MAX_ERROR_BODY_BYTES       :: 2_000

Error_Kind :: enum {
	None,
	Configuration,
	Invalid_Message,
	Timeout,
	Network,
	Authentication,
	Transient,
	Rate_Limited,
	Server,
	Validation,
	Client_Error,
	HTTP_Error,
	Malformed_Response,
}

Error :: struct {
	kind:             Error_Kind,
	status:           i64,
	retryable:        bool,
	retry_after:      string,
	response_snippet: string,
	message:          string,
}

delete_error :: proc(error: Error, allocator := context.allocator) {
	delete(error.retry_after, allocator)
	delete(error.response_snippet, allocator)
	delete(error.message, allocator)
}

Message :: struct {
	idempotency_key: string,
	sender:          string,
	to:              []string,
	cc:              []string,
	bcc:             []string,
	reply_to:        []string,
	subject:         string,
	text:            string,
	html:            string,
}

message_valid :: proc(message: ^Message) -> bool {
	return message != nil && message.sender != "" && message.subject != "" &&
	       len(message.to) + len(message.cc) + len(message.bcc) > 0 &&
	       (message.text != "" || message.html != "")
}

Transport_Request :: struct {
	url:                string,
	project_token:      string,
	body:               string,
	connect_timeout_ms: i64,
	request_timeout_ms: i64,
}

Transport_Error :: enum {
	None,
	Timeout,
	Network,
}

Transport_Response :: struct {
	status:      i64,
	body:        string,
	retry_after: string,
	error:       Transport_Error,
}

delete_transport_response :: proc(
	response: Transport_Response,
	allocator := context.allocator,
) {
	delete(response.body, allocator)
	delete(response.retry_after, allocator)
}

Transport_Proc :: #type proc(
	user_data: rawptr,
	request: ^Transport_Request,
	allocator: mem.Allocator,
) -> Transport_Response

Client_Options :: struct {
	base_url:           string,
	project_token:      string,
	connect_timeout_ms: i64,
	request_timeout_ms: i64,
	transport:          Transport_Proc,
	transport_data:     rawptr,
}

Client :: struct {
	base_url:           string,
	project_token:      string,
	connect_timeout_ms: i64,
	request_timeout_ms: i64,
	transport:          Transport_Proc,
	transport_data:     rawptr,
	allocator:          mem.Allocator,
}

delete_client :: proc(client: Client) {
	delete(client.base_url, client.allocator)
	delete(client.project_token, client.allocator)
}

Send_Result :: struct {
	message_id:    string,
	http_status:   i64,
	response_body: string,
}

delete_send_result :: proc(result: Send_Result, allocator := context.allocator) {
	delete(result.message_id, allocator)
	delete(result.response_body, allocator)
}

clone :: proc(value: string, allocator: mem.Allocator) -> (string, bool) {
	copy, error := strings.clone(value, allocator)
	return copy, error == nil
}

owned_error :: proc(
	kind: Error_Kind,
	message: string,
	allocator: mem.Allocator,
	status: i64 = 0,
	retryable := false,
	retry_after := "",
	response_snippet := "",
) -> Error {
	error := Error{kind = kind, status = status, retryable = retryable}
	error.message, _ = clone(message, allocator)
	error.retry_after, _ = clone(retry_after, allocator)
	error.response_snippet, _ = clone(response_snippet, allocator)
	return error
}

has_forbidden_header_byte :: proc(value: string) -> bool {
	return strings.contains(value, "\x00") || strings.contains(value, "\r") ||
	       strings.contains(value, "\n")
}

loopback_authority :: proc(authority: string) -> bool {
	return authority == "localhost" || strings.has_prefix(authority, "localhost:") ||
	       authority == "127.0.0.1" || strings.has_prefix(authority, "127.0.0.1:") ||
	       authority == "[::1]" || strings.has_prefix(authority, "[::1]:")
}

normalize_base_url :: proc(
	value: string,
	allocator := context.allocator,
) -> (normalized: string, ok: bool) {
	trimmed := strings.trim_space(value)
	end := len(trimmed)
	for end > 0 && trimmed[end-1] == '/' do end -= 1
	base := trimmed[:end]
	https := strings.has_prefix(base, "https://")
	http := strings.has_prefix(base, "http://")
	authority_start := 0
	if https {
		authority_start = 8
	} else if http {
		authority_start = 7
	} else {
		return
	}
	authority := base[authority_start:]
	if authority == "" || strings.contains(authority, "/") ||
	   strings.contains(authority, "@") || strings.contains(authority, "?") ||
	   strings.contains(authority, "#") || has_forbidden_header_byte(authority) ||
	   (http && !loopback_authority(authority)) {
		return
	}
	for character in transmute([]byte)authority {
		if character <= 32 || character == 127 do return
	}
	return clone(base, allocator)
}

new_client :: proc(
	options: Client_Options,
	allocator := context.allocator,
) -> (client: Client, error: Error) {
	client.allocator = allocator
	base_url, base_ok := normalize_base_url(options.base_url, allocator)
	if !base_ok {
		error = owned_error(
			.Configuration,
			"Linje base_url must be an HTTPS origin; HTTP is allowed only on loopback",
			allocator,
		)
		return
	}
	token := strings.trim_space(options.project_token)
	if token == "" || has_forbidden_header_byte(token) {
		delete(base_url, allocator)
		error = owned_error(
			.Configuration,
			"Linje project_token is required and must be safe for an HTTP header",
			allocator,
		)
		return
	}
	project_token, token_ok := clone(token, allocator)
	if !token_ok {
		delete(base_url, allocator)
		error = owned_error(.Configuration, "Could not allocate Linje client", allocator)
		return
	}
	connect_timeout_ms := options.connect_timeout_ms
	if connect_timeout_ms == 0 do connect_timeout_ms = DEFAULT_CONNECT_TIMEOUT_MS
	request_timeout_ms := options.request_timeout_ms
	if request_timeout_ms == 0 do request_timeout_ms = DEFAULT_REQUEST_TIMEOUT_MS
	if connect_timeout_ms < 0 || request_timeout_ms < 0 {
		delete(base_url, allocator)
		delete(project_token, allocator)
		error = owned_error(
			.Configuration,
			"Linje timeouts must be positive integers",
			allocator,
		)
		return
	}
	transport := options.transport
	if transport == nil do transport = curl_transport
	client = {
		base_url           = base_url,
		project_token      = project_token,
		connect_timeout_ms = connect_timeout_ms,
		request_timeout_ms = request_timeout_ms,
		transport          = transport,
		transport_data     = options.transport_data,
		allocator          = allocator,
	}
	return
}

Message_Wire :: struct {
	idempotency_key: string   `json:"idempotency-key,omitempty"`,
	sender:          string   `json:"from"`,
	to:              []string `json:"to,omitempty"`,
	cc:              []string `json:"cc,omitempty"`,
	bcc:             []string `json:"bcc,omitempty"`,
	reply_to:        []string `json:"reply-to,omitempty"`,
	subject:         string   `json:"subject"`,
	text:            string   `json:"text,omitempty"`,
	html:            string   `json:"html,omitempty"`,
}

marshal_message :: proc(
	message: ^Message,
	allocator := context.allocator,
) -> (string, bool) {
	if !message_valid(message) do return "", false
	bytes, marshal_error := json.marshal(
		Message_Wire{
			idempotency_key = message.idempotency_key,
			sender          = message.sender,
			to              = message.to,
			cc              = message.cc,
			bcc             = message.bcc,
			reply_to        = message.reply_to,
			subject         = message.subject,
			text            = message.text,
			html            = message.html,
		},
		json.Marshal_Options{spec = .JSON},
		allocator,
	)
	if marshal_error != nil do return "", false
	return transmute(string)bytes, true
}

error_kind_for_status :: proc(status: i64) -> (kind: Error_Kind, retryable: bool) {
	switch status {
	case 408:
		return .Timeout, true
	case 401, 403:
		return .Authentication, false
	case 425:
		return .Transient, true
	case 429:
		return .Rate_Limited, true
	case 400, 409, 422:
		return .Validation, false
	}
	if 500 <= status && status <= 599 do return .Server, true
	if 400 <= status && status <= 499 do return .Client_Error, false
	return .HTTP_Error, false
}

body_snippet :: proc(body: string) -> string {
	trimmed := strings.trim_space(body)
	if len(trimmed) <= MAX_ERROR_BODY_BYTES do return trimmed
	return trimmed[:MAX_ERROR_BODY_BYTES]
}

Response_Wire :: struct {
	message_id: string `json:"message-id"`,
}

send_message :: proc(
	client: ^Client,
	message: ^Message,
	allocator := context.allocator,
) -> (result: Send_Result, error: Error) {
	if client == nil || client.transport == nil || client.base_url == "" ||
	   client.project_token == "" {
		error = owned_error(
			.Configuration,
			"send_message requires a client created by new_client",
			allocator,
		)
		return
	}
	if !message_valid(message) {
		error = owned_error(
			.Invalid_Message,
			"Linje message is missing a sender, recipient, subject, or body",
			allocator,
		)
		return
	}
	payload, encoded := marshal_message(message, allocator)
	if !encoded {
		error = owned_error(
			.Invalid_Message,
			"Linje message could not be encoded as JSON",
			allocator,
		)
		return
	}
	defer delete(payload, allocator)
	url := fmt.aprintf("%s/v1/messages", client.base_url, allocator = allocator)
	defer delete(url, allocator)
	request := Transport_Request{
		url                = url,
		project_token      = client.project_token,
		body               = payload,
		connect_timeout_ms = client.connect_timeout_ms,
		request_timeout_ms = client.request_timeout_ms,
	}
	response := client.transport(client.transport_data, &request, allocator)
	defer delete_transport_response(response, allocator)
	if response.error != .None {
		kind := Error_Kind.Network
		message_text := "Linje API request failed before receiving a response"
		if response.error == .Timeout {
			kind = .Timeout
			message_text = "Linje API request timed out"
		}
		error = owned_error(kind, message_text, allocator, retryable = true)
		return
	}
	if response.status < 200 || response.status > 299 {
		kind, retryable := error_kind_for_status(response.status)
		error = owned_error(
			kind,
			"Linje API request failed",
			allocator,
			status = response.status,
			retryable = retryable,
			retry_after = response.retry_after,
			response_snippet = body_snippet(response.body),
		)
		return
	}
	wire: Response_Wire
	unmarshal_error := json.unmarshal(transmute([]byte)response.body, &wire, .JSON, allocator)
	if unmarshal_error != nil {
		error = owned_error(
			.Malformed_Response,
			"Linje API returned invalid JSON",
			allocator,
			status = response.status,
			response_snippet = body_snippet(response.body),
		)
		return
	}
	defer delete(wire.message_id, allocator)
	message_id := strings.trim_space(wire.message_id)
	if message_id == "" {
		error = owned_error(
			.Malformed_Response,
			"Linje API response did not include message-id",
			allocator,
			status = response.status,
			response_snippet = body_snippet(response.body),
		)
		return
	}
	result.message_id, _ = clone(message_id, allocator)
	result.response_body, _ = clone(response.body, allocator)
	result.http_status = response.status
	if result.message_id == "" || result.response_body == "" {
		delete_send_result(result, allocator)
		result = {}
		error = owned_error(
			.Malformed_Response,
			"Could not allocate Linje response",
			allocator,
			status = response.status,
		)
	}
	return
}
