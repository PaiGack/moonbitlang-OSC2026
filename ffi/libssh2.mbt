// libssh2 FFI declarations for MoonBit
// Binds to libssh2 C library for SSH protocol support

///|
///| pub type Session  // libssh2 session handle (C-managed lifetime)

///|
///| pub type Channel  // libssh2 channel handle (C-managed lifetime)

///|
///| pub type SockAddr  // socket address structure

///|
///| pub enum LibSSH2Error {
///|   OK = 0
///|   BAD_SOCKET = -1
///|   UNKNOWN_ERROR = -2
///|   ALLOC_ERROR = -3
///|   SOCKET_SEND_ERROR = -4
///|   SOCKET_TIMEOUT = -5
///|   INVALID_RESPONSE = -6
///|   AUTH_FAILED = -7
///|   PUBLICKEY_UNVERIFIED = -8
///|   METHOD_NONE = -9
///|   INIT_ERROR = -10
///|   INCOMPLETE = -11
///|   END_OF_FILE = -12
///|   KEYFILE_ERROR = -13
///|   AGENT_PROTOCOL_ERROR = -14
///|   AGENT_FAILED = -15
///|   SOCKET_DISCONNECT = -16
///|   INVALID_MAC = -17
///|   CONNECTION_FAILED = -18
///|   DISCONNECTED = -19
///|   HOSTKEY_INIT_ERROR = -20
///|   HOSTKEY_SIGN_ERROR = -21
///|   METHOD_COMPILE_ERROR = -22
///|   CRYPTO_ERROR = -23
///|   PUBLICKEY_PROTOCOL_ERROR = -24
///|   SERVICE_NOT_FOUND = -25
///|   PROTOCOL_ERROR = -26
///|   KEY_ALGORITHM_MISMATCH = -27
///|     INVALID_PEER = -28
///| }

///|
/// Initialize libssh2 library
///| extern "c" fn libssh2_init(flags : Int) -> Int = "moonbit_libssh2_init"

///|
/// Cleanup libssh2 library
///| extern "c" fn libssh2_exit() -> Unit = "moonbit_libssh2_exit"

///|
/// Create a new SSH session
///| extern "c" fn libssh2_session_init() -> Session = "moonbit_libssh2_session_init"

///|
/// Set blocking mode on session
///| extern "c" fn libssh2_session_set_blocking(session : Session, blocking : Int) -> Unit = "moonbit_libssh2_session_set_blocking"

///|
/// Perform SSH handshake on a socket
///| #borrow(socket)
///| extern "c" fn libssh2_session_handshake(session : Session, socket : Int) -> Int = "moonbit_libssh2_session_handshake"

///|
/// Authenticate with password
///| #borrow(username, password)
///| extern "c" fn libssh2_userauth_password(session : Session, username : Bytes, password : Bytes) -> Int = "moonbit_libssh2_userauth_password"

///|
/// Authenticate with public key
///| #borrow(username, public_key, private_key)
///| extern "c" fn libssh2_userauth_publickey(session : Session, username : Bytes, public_key : Bytes, private_key : Bytes) -> Int = "moonbit_libssh2_userauth_publickey"

///|
/// Open a new channel
///| extern "c" fn libssh2_channel_open(session : Session) -> Channel = "moonbit_libssh2_channel_open"

///|
/// Request exec on a channel
///| #borrow(command)
///| extern "c" fn libssh2_channel_exec(channel : Channel, command : Bytes) -> Int = "moonbit_libssh2_channel_exec"

///|
/// Read from channel
///| extern "c" fn libssh2_channel_read(channel : Channel, buffer : Bytes) -> Int = "moonbit_libssh2_channel_read"

///|
/// Read stderr from channel
///| extern "c" fn libssh2_channel_read_stderr(channel : Channel, buffer : Bytes) -> Int = "moonbit_libssh2_channel_read_stderr"

///|
/// Send EOF on channel
///| extern "c" fn libssh2_channel_send_eof(channel : Channel) -> Int = "moonbit_libssh2_channel_send_eof"

///|
/// Close channel
///| extern "c" fn libssh2_channel_close(channel : Channel) -> Int = "moonbit_libssh2_channel_close"

///|
/// Free channel object
///| extern "c" fn libssh2_channel_free(channel : Channel) -> Int = "moonbit_libssh2_channel_free"

///|
/// Get last error from session
///| extern "c" fn libssh2_session_last_error(session : Session) -> Bytes = "moonbit_libssh2_session_last_error"

///|
/// Check if session has authenticated
///| extern "c" fn libssh2_session_ authenticated(session : Session) -> Int = "moonbit_libssh2_session_is_authenticated"

///|
/// Free SSH session
///| extern "c" fn libssh2_session_free(session : Session) -> Int = "moonbit_libssh2_session_free"

///|
/// Get session last error code
///| extern "c" fn libssh2_session_last_errno(session : Session) -> Int = "moonbit_libssh2_session_last_errno"

///|
/// Open a TCP connection forward (for connecting to remote)
///| extern "c" fn libssh2_channel_open_direct(session : Session, host : Bytes, port : Int) -> Channel = "moonbit_libssh2_channel_open_direct"

///|
/// Request pty on channel
///| #borrow(terminal)
///| extern "c" fn libssh2_channel_request_pty(channel : Channel, terminal : Bytes) -> Int = "moonbit_libssh2_channel_request_pty"

///|
/// Request shell on channel
///| extern "c" fn libssh2_channel_request_pty_shell(channel : Channel) -> Int = "moonbit_libssh2_channel_request_pty_shell"

///|
/// Get channel exit status
///| extern "c" fn libssh2_channel_get_exit_status(channel : Channel) -> Int = "moonbit_libssh2_channel_get_exit_status"

///|
/// Get channel eof status
///| extern "c" fn libssh2_channel_eof(channel : Channel) -> Int = "moonbit_libssh2_channel_eof"

///|
/// Check if channel is closed
///| extern "c" fn libssh2_channel_is_closed(channel : Channel) -> Int = "moonbit_libssh2_channel_is_closed"