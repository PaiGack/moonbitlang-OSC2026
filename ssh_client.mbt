// SSH Client Library for MoonBit
// Implements SSH transport layer, authentication, and exec functionality
// Uses libssh2 for SSH protocol and native TCP sockets

// ============================================================================
// SSH Protocol Types and Constants
// ============================================================================

pub type SSH  // SSH client type marker

// ============================================================================
// Connection State
// ============================================================================

pub struct Connection {
  socket: Socket
  session: Session
  mut channel: Channel?
  mut authenticated: Bool
  host: String
  port: Int
}

// ============================================================================
// Socket FFI Functions (from ffi/socket.mbt)
// ============================================================================

type Socket

extern "c" fn socket_create() -> Socket = "moonbit_socket_create"

extern "c" fn socket_connect(socket : Socket, host : Bytes, port : Int) -> Int = "moonbit_socket_connect"

extern "c" fn socket_send(socket : Socket, data : Bytes) -> Int = "moonbit_socket_send"

extern "c" fn socket_receive(socket : Socket, buffer : Bytes) -> Int = "moonbit_socket_receive"

extern "c" fn socket_close(socket : Socket) -> Int = "moonbit_socket_close"

extern "c" fn socket_get_fd(socket : Socket) -> Int = "moonbit_socket_get_fd"

// ============================================================================
// LibSSH2 FFI Functions (from ffi/libssh2.mbt)
// ============================================================================

type Session

type Channel

extern "c" fn libssh2_init(flags : Int) -> Int = "moonbit_libssh2_init"

extern "c" fn libssh2_exit() -> Unit = "moonbit_libssh2_exit"

extern "c" fn libssh2_session_init() -> Session = "moonbit_libssh2_session_init"

extern "c" fn libssh2_session_set_blocking(session : Session, blocking : Int) -> Unit = "moonbit_libssh2_session_set_blocking"

extern "c" fn libssh2_session_handshake(session : Session, socket : Int) -> Int = "moonbit_libssh2_session_handshake"

extern "c" fn libssh2_userauth_password(session : Session, username : Bytes, password : Bytes) -> Int = "moonbit_libssh2_userauth_password"

extern "c" fn libssh2_userauth_publickey(session : Session, username : Bytes, public_key : Bytes, private_key : Bytes) -> Int = "moonbit_libssh2_userauth_publickey"

extern "c" fn libssh2_channel_open(session : Session) -> Channel = "moonbit_libssh2_channel_open"

extern "c" fn libssh2_channel_exec(channel : Channel, command : Bytes) -> Int = "moonbit_libssh2_channel_exec"

extern "c" fn libssh2_channel_read(channel : Channel, buffer : Bytes) -> Int = "moonbit_libssh2_channel_read"

extern "c" fn libssh2_channel_read_stderr(channel : Channel, buffer : Bytes) -> Int = "moonbit_libssh2_channel_read_stderr"

extern "c" fn libssh2_channel_send_eof(channel : Channel) -> Int = "moonbit_libssh2_channel_send_eof"

extern "c" fn libssh2_channel_close(channel : Channel) -> Int = "moonbit_libssh2_channel_close"

extern "c" fn libssh2_channel_free(channel : Channel) -> Int = "moonbit_libssh2_channel_free"

extern "c" fn libssh2_session_last_error(session : Session) -> Bytes = "moonbit_libssh2_session_last_error"

extern "c" fn libssh2_session_is_authenticated(session : Session) -> Int = "moonbit_libssh2_session_is_authenticated"

extern "c" fn libssh2_session_free(session : Session) -> Int = "moonbit_libssh2_session_free"

extern "c" fn libssh2_session_last_errno(session : Session) -> Int = "moonbit_libssh2_session_last_errno"

extern "c" fn libssh2_channel_get_exit_status(channel : Channel) -> Int = "moonbit_libssh2_channel_get_exit_status"

extern "c" fn libssh2_channel_eof(channel : Channel) -> Int = "moonbit_libssh2_channel_eof"

extern "c" fn libssh2_channel_is_closed(channel : Channel) -> Int = "moonbit_libssh2_channel_is_closed"

// ============================================================================
// Utility Functions
// ============================================================================

fn string_to_bytes(s : String) -> Bytes {
  s.to_bytes()
}

fn bytes_to_string(b : Bytes) -> String {
  b.to_string()
}

// ============================================================================
// SSH Implementation
// ============================================================================

/// Connect to an SSH server
pub fn SSH::connect(host: String, port: Int) -> Result[Connection, String] {
  // Initialize libssh2
  let init_result = libssh2_init(0)
  if init_result != 0 {
    return Err("Failed to initialize libssh2")
  }

  // Create TCP socket
  let socket = socket_create()

  // Convert host to bytes for FFI
  let host_bytes = string_to_bytes(host)

  // Connect to host
  let connect_result = socket_connect(socket, host_bytes, port)
  if connect_result != 0 {
    ignore(socket_close(socket))
    libssh2_exit()
    return Err("Failed to connect to \{host}:\{port}")
  }

  // Create SSH session
  let session = libssh2_session_init()

  // Set blocking mode
  libssh2_session_set_blocking(session, 1)

  // Perform SSH handshake
  let socket_fd = socket_get_fd(socket)
  let handshake_result = libssh2_session_handshake(session, socket_fd)
  if handshake_result != 0 {
    let error = libssh2_session_last_error(session)
    ignore(libssh2_session_free(session))
    ignore(socket_close(socket))
    libssh2_exit()
    return Err("SSH handshake failed: \{bytes_to_string(error)}")
  }

  let conn : Connection = {
    socket,
    session,
    channel: None,
    authenticated: false,
    host,
    port,
  }

  Ok(conn)
}

/// Authenticate with password
pub fn Connection::auth_password(self : Connection, username: String, password: String) -> Result[Unit, String] {
  if self.authenticated {
    return Err("Already authenticated")
  }

  let user_bytes = string_to_bytes(username)
  let pass_bytes = string_to_bytes(password)

  let result = libssh2_userauth_password(self.session, user_bytes, pass_bytes)
  if result != 0 {
    let error = libssh2_session_last_error(self.session)
    return Err("Password authentication failed: \{bytes_to_string(error)}")
  }

  self.authenticated = true
  Ok(())
}

/// Authenticate with public key
pub fn Connection::auth_publickey(self : Connection, username: String, public_key: String, private_key: String) -> Result[Unit, String] {
  if self.authenticated {
    return Err("Already authenticated")
  }

  let user_bytes = string_to_bytes(username)
  let pub_bytes = string_to_bytes(public_key)
  let priv_bytes = string_to_bytes(private_key)

  let result = libssh2_userauth_publickey(self.session, user_bytes, pub_bytes, priv_bytes)
  if result != 0 {
    let error = libssh2_session_last_error(self.session)
    return Err("Public key authentication failed: \{bytes_to_string(error)}")
  }

  self.authenticated = true
  Ok(())
}

/// Execute a command on the remote server
pub fn Connection::exec(self : Connection, command: String) -> Result[String, String] {
  if not(self.authenticated) {
    return Err("Not authenticated - please call auth_password first")
  }

  // Open a new channel
  let channel = libssh2_channel_open(self.session)

  // Execute command on the channel
  let cmd_bytes = string_to_bytes(command)
  let exec_result = libssh2_channel_exec(channel, cmd_bytes)
  if exec_result != 0 {
    let error = libssh2_session_last_error(self.session)
    ignore(libssh2_channel_free(channel))
    return Err("Failed to execute command: \{bytes_to_string(error)}")
  }

  // Read output from the channel
  let output = @buffer.Buffer::new(size_hint=4096)
  let receive_buf = Bytes::make(4096, 0)

  loop {
    // Try to read from channel
    let n = libssh2_channel_read(channel, receive_buf)
    if n <= 0 {
      break
    }
    // Append the bytes we read to the output buffer
    let slice = receive_buf[0:n]
    output.write_sub_string(bytes_to_string(slice), 0, n)
  }

  // Get exit status
  let exit_status = libssh2_channel_get_exit_status(channel)

  // Close the channel
  ignore(libssh2_channel_send_eof(channel))
  ignore(libssh2_channel_close(channel))
  ignore(libssh2_channel_free(channel))

  if exit_status != 0 {
    return Err("Command exited with status \{exit_status}")
  }

  Ok(output.to_string())
}

/// Close the SSH connection
pub fn Connection::close(self : Connection) -> Unit {
  // Close channel if open
  match self.channel {
    Some(ch) => {
      ignore(libssh2_channel_send_eof(ch))
      ignore(libssh2_channel_close(ch))
      ignore(libssh2_channel_free(ch))
    }
    None => ()
  }

  // Free session and close socket
  ignore(libssh2_session_free(self.session))
  ignore(socket_close(self.socket))
  libssh2_exit()
}
