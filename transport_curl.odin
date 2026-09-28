package linje

import "base:runtime"
import c "core:c/libc"
import "core:fmt"
import "core:mem"
import "core:strings"
import "core:sync"

Curl :: struct {}
Slist :: struct {
	data: cstring,
	next: ^Slist,
}
Curl_Code :: distinct c.int
Curl_Option :: distinct c.int
Curl_Info :: distinct c.int
Curl_Off_T :: i64
Curl_Write_Callback :: #type proc "c"([^]byte, c.size_t, c.size_t, rawptr) -> c.size_t

CURL_OK                      :: Curl_Code(0)
CURL_OPERATION_TIMED_OUT     :: Curl_Code(28)
CURL_GLOBAL_DEFAULT          :: c.long(3)
CURL_OPT_WRITEDATA           :: Curl_Option(10_001)
CURL_OPT_URL                 :: Curl_Option(10_002)
CURL_OPT_POST                :: Curl_Option(47)
CURL_OPT_POSTFIELDS          :: Curl_Option(10_015)
CURL_OPT_POSTFIELDSIZE_LARGE :: Curl_Option(30_120)
CURL_OPT_HTTPHEADER          :: Curl_Option(10_023)
CURL_OPT_HEADERDATA          :: Curl_Option(10_029)
CURL_OPT_WRITEFUNCTION       :: Curl_Option(20_011)
CURL_OPT_HEADERFUNCTION      :: Curl_Option(20_079)
CURL_OPT_FOLLOWLOCATION      :: Curl_Option(52)
CURL_OPT_PROTOCOLS_STR       :: Curl_Option(10_318)
CURL_OPT_REDIR_PROTOCOLS_STR :: Curl_Option(10_319)
CURL_OPT_SSL_VERIFYPEER      :: Curl_Option(64)
CURL_OPT_SSL_VERIFYHOST      :: Curl_Option(81)
CURL_OPT_CONNECTTIMEOUT_MS   :: Curl_Option(156)
CURL_OPT_TIMEOUT_MS          :: Curl_Option(155)
CURL_OPT_NOSIGNAL            :: Curl_Option(99)
CURL_OPT_USERAGENT           :: Curl_Option(10_018)
CURL_INFO_RESPONSE_CODE      :: Curl_Info(0x20_0002)

foreign import curl_lib "system:curl"

@(default_calling_convention = "c", link_prefix = "curl_")
foreign curl_lib {
	global_init    :: proc(flags: c.long) -> Curl_Code ---
	easy_init      :: proc() -> ^Curl ---
	easy_setopt    :: proc(handle: ^Curl, option: Curl_Option, #c_vararg args: ..any) -> Curl_Code ---
	easy_perform   :: proc(handle: ^Curl) -> Curl_Code ---
	easy_getinfo   :: proc(handle: ^Curl, info: Curl_Info, #c_vararg args: ..any) -> Curl_Code ---
	easy_cleanup   :: proc(handle: ^Curl) ---
	slist_append   :: proc(list: ^Slist, data: cstring) -> ^Slist ---
	slist_free_all :: proc(list: ^Slist) ---
}

curl_once: sync.Once
curl_ready: bool

curl_initialize :: proc() {
	curl_ready = global_init(CURL_GLOBAL_DEFAULT) == CURL_OK
}

Curl_Transfer :: struct {
	body:        [dynamic]byte,
	retry_after: string,
	overflow:    bool,
	allocator:   mem.Allocator,
}

MAX_RESPONSE_BODY_BYTES :: 2 * 1024 * 1024

curl_write :: proc "c"(
	buffer: [^]byte,
	size, count: c.size_t,
	user_data: rawptr,
) -> c.size_t {
	context = runtime.default_context()
	transfer := cast(^Curl_Transfer)user_data
	if transfer == nil do return 0
	byte_count := int(size * count)
	if byte_count < 0 || byte_count > MAX_RESPONSE_BODY_BYTES - len(transfer.body) {
		transfer.overflow = true
		return 0
	}
	append(&transfer.body, ..buffer[:byte_count])
	return c.size_t(byte_count)
}

ascii_lower :: proc(value: byte) -> byte {
	if 'A' <= value && value <= 'Z' do return value + ('a' - 'A')
	return value
}

ascii_prefix_equal_fold :: proc(value, prefix: string) -> bool {
	if len(value) < len(prefix) do return false
	for character, index in transmute([]byte)prefix {
		if ascii_lower(value[index]) != ascii_lower(character) do return false
	}
	return true
}

curl_header :: proc "c"(
	buffer: [^]byte,
	size, count: c.size_t,
	user_data: rawptr,
) -> c.size_t {
	context = runtime.default_context()
	transfer := cast(^Curl_Transfer)user_data
	if transfer == nil do return 0
	byte_count := int(size * count)
	if byte_count <= 0 do return c.size_t(byte_count)
	line := string(buffer[:byte_count])
	prefix := "retry-after:"
	if ascii_prefix_equal_fold(line, prefix) {
		value := strings.trim_space(line[len(prefix):])
		copy, copy_error := strings.clone(value, transfer.allocator)
		if copy_error == nil {
			delete(transfer.retry_after, transfer.allocator)
			transfer.retry_after = copy
		}
	}
	return c.size_t(byte_count)
}

curl_setopt_ok :: proc(handle: ^Curl, option: Curl_Option, value: $T) -> bool {
	return easy_setopt(handle, option, value) == CURL_OK
}

curl_transport :: proc(
	_: rawptr,
	request: ^Transport_Request,
	allocator: mem.Allocator,
) -> (response: Transport_Response) {
	if request == nil || has_forbidden_header_byte(request.url) ||
	   has_forbidden_header_byte(request.project_token) {
		response.error = .Network
		return
	}
	sync.once_do(&curl_once, curl_initialize)
	if !curl_ready {
		response.error = .Network
		return
	}
	url_c := strings.clone_to_cstring(request.url, context.temp_allocator) or_else nil
	if url_c == nil {
		response.error = .Network
		return
	}
	handle := easy_init()
	if handle == nil {
		response.error = .Network
		return
	}
	defer easy_cleanup(handle)
	headers: ^Slist
	headers = slist_append(headers, "Accept: application/json")
	headers = slist_append(headers, "Content-Type: application/json")
	headers = slist_append(headers, "Expect:")
	authorization := fmt.aprintf(
		"Authorization: Bearer %s",
		request.project_token,
		allocator = context.temp_allocator,
	)
	authorization_c := strings.clone_to_cstring(authorization, context.temp_allocator) or_else nil
	if authorization_c != nil do headers = slist_append(headers, authorization_c)
	if headers == nil || authorization_c == nil {
		if headers != nil do slist_free_all(headers)
		response.error = .Network
		return
	}
	defer slist_free_all(headers)
	transfer := Curl_Transfer{
		body      = make([dynamic]byte, 0, 4096, allocator),
		allocator = allocator,
	}
	defer delete(transfer.body)
	defer delete(transfer.retry_after, allocator)
	configured :=
		curl_setopt_ok(handle, CURL_OPT_URL, url_c) &&
		curl_setopt_ok(handle, CURL_OPT_POST, c.long(1)) &&
		curl_setopt_ok(handle, CURL_OPT_POSTFIELDS, raw_data(request.body)) &&
		curl_setopt_ok(handle, CURL_OPT_POSTFIELDSIZE_LARGE, Curl_Off_T(len(request.body))) &&
		curl_setopt_ok(handle, CURL_OPT_HTTPHEADER, headers) &&
		curl_setopt_ok(handle, CURL_OPT_WRITEFUNCTION, Curl_Write_Callback(curl_write)) &&
		curl_setopt_ok(handle, CURL_OPT_WRITEDATA, &transfer) &&
		curl_setopt_ok(handle, CURL_OPT_HEADERFUNCTION, Curl_Write_Callback(curl_header)) &&
		curl_setopt_ok(handle, CURL_OPT_HEADERDATA, &transfer) &&
		curl_setopt_ok(handle, CURL_OPT_FOLLOWLOCATION, c.long(0)) &&
		curl_setopt_ok(handle, CURL_OPT_PROTOCOLS_STR, cstring("https,http")) &&
		curl_setopt_ok(handle, CURL_OPT_REDIR_PROTOCOLS_STR, cstring("https,http")) &&
		curl_setopt_ok(handle, CURL_OPT_SSL_VERIFYPEER, c.long(1)) &&
		curl_setopt_ok(handle, CURL_OPT_SSL_VERIFYHOST, c.long(2)) &&
		curl_setopt_ok(handle, CURL_OPT_CONNECTTIMEOUT_MS, c.long(request.connect_timeout_ms)) &&
		curl_setopt_ok(handle, CURL_OPT_TIMEOUT_MS, c.long(request.request_timeout_ms)) &&
		curl_setopt_ok(handle, CURL_OPT_NOSIGNAL, c.long(1)) &&
		curl_setopt_ok(handle, CURL_OPT_USERAGENT, cstring("odin-linje/0.1"))
	if !configured {
		response.error = .Network
		return
	}
	code := easy_perform(handle)
	status: c.long
	_ = easy_getinfo(handle, CURL_INFO_RESPONSE_CODE, &status)
	if code != CURL_OK || transfer.overflow {
		response.error = .Network
		if code == CURL_OPERATION_TIMED_OUT do response.error = .Timeout
		return
	}
	response.status = i64(status)
	response.body, _ = clone(string(transfer.body[:]), allocator)
	response.retry_after, _ = clone(transfer.retry_after, allocator)
	return
}
