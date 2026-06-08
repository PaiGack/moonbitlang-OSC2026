///|
/// MoonSSH 顶层 API。
///
/// 典型使用方式：
///   let conn = @async.TCP::connect(host, port)
///   let client = Client::new(conn)
///   let banner = client.read_server_banner()
///   client.send_client_banner()
///   client.kex()
///   client.auth_password("alice", "hunter2")
///   let ch = client.open_session()
///   let output = client.exec(ch, "ls -l")
///
/// 详细字段：
///   - `host_key_verifier`: 接收 (alg, key_bytes) 并允许/拒绝。
///   - `first_kex_follows_follows`: KEXINIT 标志位。
///   - 实际传输由底层的 `@async.TCP` 提供。

///|
/// Connect options.
pub struct ConnectOptions {
  host : String
  port : Int
  user : String
  /// If set, override the default banner. Otherwise we send
  /// `SSH-2.0-MoonSSH_0.1.0`.
  client_banner : String?
  /// Host key verifier (returns true to accept, false to reject).
  accept_host_key : (String, Bytes) -> Bool
  /// Connect timeout in milliseconds (0 = no timeout).
  timeout_ms : Int
}

///|
pub fn ConnectOptions::new(host : String, port : Int, user : String) -> ConnectOptions {
  {
    host,
    port,
    user,
    client_banner: None,
    accept_host_key: (_alg, _key) => true,
    timeout_ms: 30_000,
  }
}

///|
pub fn ConnectOptions::with_host_key_verifier(
  self : ConnectOptions,
  f : (String, Bytes) -> Bool,
) -> ConnectOptions {
  { ..self, accept_host_key: f }
}

///|
pub fn ConnectOptions::with_banner(self : ConnectOptions, banner : String) -> ConnectOptions {
  { ..self, client_banner: Some(banner) }
}

///|
/// Top-level client handle. Owns the connection state.
pub struct Client {
  priv conn : ClientConn
  priv banner_client : String
  priv banner_server : String
  priv kex : KexContext
  priv auth : AuthContext
  priv session_id : Bytes
  mut next_channel_id : Int
}

///|
priv enum ClientConn {
  Connected(@socket.Tcp)
}

///|
pub fn Client::default_banner() -> String {
  "SSH-2.0-MoonSSH_0.1.0"
}

///|
/// Connect to an SSH server and complete the banner exchange.
/// Does NOT yet run KEX or auth; call `kex` and `auth_*` afterwards.
pub fn Client::connect(opts : ConnectOptions) -> Client raise SshError {
  let conn = @socket.Tcp::connect_to_host(opts.host, port=opts.port) catch {
    e => raise IoError("connect: \{e}")
  }
  let client_banner = match opts.client_banner {
    Some(b) => b
    None => Client::default_banner()
  }
  // Send client banner (line ending with \r\n)
  conn.write("\{client_banner}\r\n") catch {
    e => raise IoError("write banner: \{e}")
  }
  // Read server banner
  let banner_line = read_line(conn) catch {
    e => raise IoError("read banner: \{e}")
  }
  if not(banner_line.has_prefix("SSH-")) {
    raise ProtocolError("server banner missing SSH- prefix: \{banner_line}")
  }
  let v_c = @utf8.encode("\{client_banner}\r\n")
  let v_s = @utf8.encode("\{banner_line}\r\n")
  let kex = KexContext::new(v_c, v_s)
  let auth = AuthContext::new(opts.user)
  { conn: Connected(conn), banner_client: client_banner, banner_server: banner_line, kex, auth, session_id: b"", next_channel_id: 0 }
}

///|
/// Run the SSH key exchange (KEXINIT / KEXDH / NEWKEYS).
/// v0.1: stub — real implementation is `KexContext::drive` with the
/// concrete transport; that loop is left as a TODO (Step 4.2).
pub fn Client::kex(self : Client) -> Unit raise SshError {
  self.kex.drive(stub_read, stub_write)
}

///|
fn stub_read() -> Bytes raise SshError {
  b""
}

///|
fn stub_write(_b : Bytes) -> Unit raise SshError {
  ()
}

///|
/// Authenticate with a password.
pub fn Client::auth_password(
  self : Client,
  password : String,
) -> Unit raise SshError {
  ignore(self.auth.build_password(password))
  // TODO(Step 4.3): wire to the transport; wait for `Success` reply.
  self.auth.apply_reply(Success)
}

///|
/// Authenticate with a public key.
pub fn Client::auth_publickey(
  self : Client,
  _key : Bytes,
  _signature : Bytes,
) -> Unit raise SshError {
  // TODO(Step 4.3): wire to the transport.
  self.auth.apply_reply(Success)
}

///|
/// Open a new session channel.
pub fn Client::open_session(self : Client) -> Channel {
  let id = self.next_channel_id
  self.next_channel_id = self.next_channel_id + 1
  Channel::new(id, self.session_id)
}

///|
/// Send an `exec` request and read the resulting stdout / exit-status.
/// v0.1: stub — needs the full transport + channel pump.
pub fn Client::exec(
  _self : Client,
  _channel : Channel,
  _command : String,
) -> String {
  abort("Client::exec: not yet implemented (v0.1 stub — see docs/prd_001.md §Step 4.5)")
}

///|
/// Close the SSH connection cleanly (sends DISCONNECT if possible).
pub fn Client::close(self : Client) -> Unit {
  // TODO(Step 4.7): send SSH_MSG_DISCONNECT (type 1) before closing the
  // transport. v0.1 just drops the connection.
  ignore(self)
}

// --- Internal helpers -----------------------------------------------

///|
fn read_line(_conn : @socket.Tcp) -> String raise SshError {
  // TODO(Step 4.7): proper line-reading. v0.1 reads a fixed buffer.
  // The actual reader needs to handle \r\n line endings and the SSH
  // maximum banner length.
  raise IoError("read_line: not yet implemented")
}
