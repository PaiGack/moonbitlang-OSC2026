// SSH Client Library for MoonBit
// Implements SSH transport layer, authentication, and exec functionality
// Uses libssh2 for SSH protocol and native TCP sockets

// ============================================================================
// SSH Protocol Types and Constants
// ============================================================================

///| pub type SSH  // SSH client type marker

// ============================================================================
// Connection State
// ============================================================================

///| pub struct Connection {
///|   socket: Socket
///|   session: Session
///|   channel: Channel?
///|   authenticated: Bool
///|   host: String
///|   port: Int
///| }

// ============================================================================
// SSH Packet Type Definitions
// ============================================================================

///| enum PacketType as Byte {
///|   Disconnect = 1
///|   Ignore = 2
///|   Unimplemented = 3
///|   Debug = 4
///|   ServiceRequest = 5
///|   ServiceAccept = 6
///|   KexInit = 20
///|   NewKeys = 21
///|   RequestSuccess = 101
///|   RequestFailure = 102
///|   ChannelOpen = 90
///|   ChannelOpenConfirmation = 91
///|   ChannelOpenFailure = 92
///|   ChannelWindowAdjust = 93
///|   ChannelData = 94
///|   ChannelExtendedData = 95
///|   ChannelEof = 96
///|   ChannelClose = 97
///|   ChannelRequest = 98
///|   ChannelSuccess = 99
///|   ChannelFailure = 100
///|   UserauthRequest = 50
///|   UserauthSuccess = 52
///|   UserauthFailure = 51
///|   UserauthBanner = 53
///| }

// SSH Disconnect reason codes
///| pub const DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT : Int = 1
///| pub const DISCONNECT_PROTOCOL_ERROR : Int = 2
///| pub const DISCONNECT_KEY_EXCHANGE_FAILED : Int = 3
///| pub const DISCONNECT_RESERVED : Int = 4
///| pub const DISCONNECT_MAC_ERROR : Int = 5
///| pub const DISCONNECT_COMPRESSION_ERROR : Int = 6
///| pub const DISCONNECT_SERVICE_NOT_AVAILABLE : Int = 7
///| pub const DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED : Int = 8
///| pub const DISCONNECT_HOST_KEY_NOT_VERIFIABLE : Int = 9
///| pub const DISCONNECT_CONNECTION_LOST : Int = 10
///| pub const DISCONNECT_BY_APPLICATION : Int = 11
///| pub const DISCONNECT_TOO_MANY_CONNECTIONS : Int = 12

// ============================================================================
// Socket FFI Functions (from ffi/socket.mbt)
// ============================================================================

///| type Socket

///| extern "c" fn socket_create() -> Socket = "moonbit_socket_create"

///| #borrow(host)
///| extern "c" fn socket_connect(socket : Socket, host : Bytes, port : Int) -> Int = "moonbit_socket_connect"

///| extern "c" fn socket_send(socket : Socket, data : Bytes) -> Int = "moonbit_socket_send"

///| extern "c" fn socket_receive(socket : Socket, buffer : Bytes) -> Int = "moonbit_socket_receive"

///| extern "c" fn socket_close(socket : Socket) -> Int = "moonbit_socket_close"

///| extern "c" fn socket_get_fd(socket : Socket) -> Int = "moonbit_socket_get_fd"

// ============================================================================
// LibSSH2 FFI Functions (from ffi/libssh2.mbt)
// ============================================================================

///| type Session

///| type Channel

///| extern "c" fn libssh2_init(flags : Int) -> Int = "moonbit_libssh2_init"

///| extern "c" fn libssh2_exit() -> Unit = "moonbit_libssh2_exit"

///| extern "c" fn libssh2_session_init() -> Session = "moonbit_libssh2_session_init"

///| extern "c" fn libssh2_session_set_blocking(session : Session, blocking : Int) -> Unit = "moonbit_libssh2_session_set_blocking"

///| #borrow(socket)
///| extern "c" fn libssh2_session_handshake(session : Session, socket : Int) -> Int = "moonbit_libssh2_session_handshake"

///| #borrow(username, password)
///| extern "c" fn libssh2_userauth_password(session : Session, username : Bytes, password : Bytes) -> Int = "moonbit_libssh2_userauth_password"

///| #borrow(username, public_key, private_key)
///| extern "c" fn libssh2_userauth_publickey(session : Session, username : Bytes, public_key : Bytes, private_key : Bytes) -> Int = "moonbit_libssh2_userauth_publickey"

///| extern "c" fn libssh2_channel_open(session : Session) -> Channel = "moonbit_libssh2_channel_open"

///| #borrow(command)
///| extern "c" fn libssh2_channel_exec(channel : Channel, command : Bytes) -> Int = "moonbit_libssh2_channel_exec"

///| extern "c" fn libssh2_channel_read(channel : Channel, buffer : Bytes) -> Int = "moonbit_libssh2_channel_read"

///| extern "c" fn libssh2_channel_read_stderr(channel : Channel, buffer : Bytes) -> Int = "moonbit_libssh2_channel_read_stderr"

///| extern "c" fn libssh2_channel_send_eof(channel : Channel) -> Int = "moonbit_libssh2_channel_send_eof"

///| extern "c" fn libssh2_channel_close(channel : Channel) -> Int = "moonbit_libssh2_channel_close"

///| extern "c" fn libssh2_channel_free(channel : Channel) -> Int = "moonbit_libssh2_channel_free"

///| extern "c" fn libssh2_session_last_error(session : Session) -> Bytes = "moonbit_libssh2_session_last_error"

///| extern "c" fn libssh2_session_is_authenticated(session : Session) -> Int = "moonbit_libssh2_session_is_authenticated"

///| extern "c" fn libssh2_session_free(session : Session) -> Int = "moonbit_libssh2_session_free"

///| extern "c" fn libssh2_session_last_errno(session : Session) -> Int = "moonbit_libssh2_session_last_errno"

///| extern "c" fn libssh2_channel_get_exit_status(channel : Channel) -> Int = "moonbit_libssh2_channel_get_exit_status"

///| extern "c" fn libssh2_channel_eof(channel : Channel) -> Int = "moonbit_libssh2_channel_eof"

///| extern "c" fn libssh2_channel_is_closed(channel : Channel) -> Int = "moonbit_libssh2_channel_is_closed"

// ============================================================================
// Utility Functions
// ============================================================================

// Note: For FFI with libssh2, we use String.to_bytes() to get raw UTF-8 bytes
// The C stubs handle string conversion internally
fn string_to_bytes(s : String) -> Bytes {
  s.to_bytes()
}

fn bytes_to_string(b : Bytes) -> String {
  // Use built-in Bytes.to_string() for lossy conversion
  b.to_string()
}

// ============================================================================
// SSH Implementation
// ============================================================================

///| impl SSH {
///|   ///| Connect to an SSH server
///|   pub fn SSH::connect(host: String, port: Int) -> Result[Connection, String] {
///|     // Initialize libssh2
///|     let init_result = libssh2_init(0)
///|     if init_result != 0 {
///|       return Err("Failed to initialize libssh2")
///|     }
///
///     // Create TCP socket
///|     let socket = socket_create()
///|     if socket == 0 as Socket {
///|       libssh2_exit()
///|       return Err("Failed to create socket")
///|     }
///
///     // Convert host to bytes for FFI
///|     let host_bytes = string_to_bytes(host)
///
///     // Connect to host
///|     let connect_result = socket_connect(socket, host_bytes, port)
///|     if connect_result != 0 {
///|       socket_close(socket)
///|       libssh2_exit()
///|       return Err("Failed to connect to \{host}:\{port}")
///|     }
///
///     // Create SSH session
///|     let session = libssh2_session_init()
///|     if session == 0 as Session {
///|       socket_close(socket)
///|       libssh2_exit()
///|       return Err("Failed to create SSH session")
///|     }
///
///     // Set blocking mode
///|     libssh2_session_set_blocking(session, 1)
///
///     // Perform SSH handshake
///|     let socket_fd = socket_get_fd(socket)
///|     let handshake_result = libssh2_session_handshake(session, socket_fd)
///|     if handshake_result != 0 {
///|       let error = libssh2_session_last_error(session)
///|       libssh2_session_free(session)
///|       socket_close(socket)
///|       libssh2_exit()
///|       return Err("SSH handshake failed: \{bytes_to_string(error)}")
///|     }
///
///     let conn : Connection = {
///|       socket: socket,
///|       session: session,
///|       channel: None,
///|       authenticated: false,
///|       host: host,
///|       port: port,
///|     }
///
///|     Ok(conn)
///|   }
///
///   ///| Authenticate with password
///|   pub fn auth_password(self: Connection, username: String, password: String) -> Result[Unit, String] {
///|     if self.authenticated {
///|       return Err("Already authenticated")
///|     }
///
///     let user_bytes = string_to_bytes(username)
///     let pass_bytes = string_to_bytes(password)
///
///     let result = libssh2_userauth_password(self.session, user_bytes, pass_bytes)
///     if result != 0 {
///|       let error = libssh2_session_last_error(self.session)
///|       return Err("Password authentication failed: \{bytes_to_string(error)}")
///|     }
///
///     Ok(())
///|   }
///
///   ///| Authenticate with public key
///|   pub fn auth_publickey(self: Connection, username: String, public_key: String, private_key: String) -> Result[Unit, String] {
///|     if self.authenticated {
///|       return Err("Already authenticated")
///|     }
///
///     let user_bytes = string_to_bytes(username)
///     let pub_bytes = string_to_bytes(public_key)
///     let priv_bytes = string_to_bytes(private_key)
///
///     let result = libssh2_userauth_publickey(self.session, user_bytes, pub_bytes, priv_bytes)
///     if result != 0 {
///|       let error = libssh2_session_last_error(self.session)
///|       return Err("Public key authentication failed: \{bytes_to_string(error)}")
///|     }
///
///     Ok(())
///|   }
///
///   ///| Execute a command on the remote server
///|   pub fn exec(self: Connection, command: String) -> Result[String, String] {
///|     if not self.authenticated {
///|       return Err("Not authenticated - please call auth_password first")
///|     }
///
///     // Open a new channel
///|     let channel = libssh2_channel_open(self.session)
///|     if channel == 0 as Channel {
///|       let error = libssh2_session_last_error(self.session)
///|       return Err("Failed to open channel: \{bytes_to_string(error)}")
///|     }
///
///     // Execute command on the channel
///|     let cmd_bytes = string_to_bytes(command)
///|     let exec_result = libssh2_channel_exec(channel, cmd_bytes)
///|     if exec_result != 0 {
///|       let error = libssh2_session_last_error(self.session)
///|       libssh2_channel_free(channel)
///|       return Err("Failed to execute command: \{bytes_to_string(error)}")
///|     }
///
///     // Read output from the channel
///|     let mut output = @buffer.Buffer::new(4096)
///|     let receive_buf : Bytes = @buffer.Buffer::new(4096).view().to_bytes()
///|
///|     loop {
///|       // Try to read from channel - use buffer approach
///|       let n = libssh2_channel_read(channel, receive_buf)
///|       if n <= 0 {
///|         break
///|       }
///|     }
///
///     // Get exit status
///|     let exit_status = libssh2_channel_get_exit_status(channel)
///
///     // Close the channel
///|     libssh2_channel_send_eof(channel)
///|     libssh2_channel_close(channel)
///|     libssh2_channel_free(channel)
///
///     if exit_status != 0 {
///|       return Err("Command exited with status \{exit_status}")
///|     }
///
///     Ok("")  // Return empty string (actual output reading needs more work)
///|   }
///
///   ///| Close the SSH connection
///|   pub fn close(self: Connection) -> Unit {
///|     // Close channel if open
///|     match self.channel {
///|       Some(ch) => {
///|         libssh2_channel_send_eof(ch)
///|         libssh2_channel_close(ch)
///|         libssh2_channel_free(ch)
///|       }
///|       None => ()
///|     }
///
///     // Free session and close socket
///|     libssh2_session_free(self.session)
///|     socket_close(self.socket)
///|     libssh2_exit()
///|   }
///| }