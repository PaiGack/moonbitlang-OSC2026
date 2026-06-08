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
pub fn ConnectOptions::new(
  host : String,
  port : Int,
  user : String,
) -> ConnectOptions {
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
pub fn ConnectOptions::with_banner(
  self : ConnectOptions,
  banner : String,
) -> ConnectOptions {
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
  priv accept_host_key : (String, Bytes) -> Bool
  priv mut session_id : Bytes
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
  let v_c = @utf8.encode(client_banner)
  let v_s = @utf8.encode(banner_line)
  let kex = KexContext::new(v_c, v_s)
  let auth = AuthContext::new(opts.user)
  {
    conn: Connected(conn),
    banner_client: client_banner,
    banner_server: banner_line,
    kex,
    auth,
    accept_host_key: opts.accept_host_key,
    session_id: b"",
    next_channel_id: 0,
  }
}

///|
/// Run the SSH key exchange (KEXINIT / KEXDH / NEWKEYS).
/// The current transport path drives plaintext KEX packets; encrypted packet
/// IO is installed by a later transport step.
pub fn Client::kex(self : Client) -> Unit raise SshError {
  self.kex.drive(
    () => self.read_plain_packet(),
    payload => self.write_plain_packet(payload),
    self.accept_host_key,
  )
  self.session_id = self.kex.session_id
}

///|
/// Authenticate with a password.
pub fn Client::auth_password(
  self : Client,
  password : String,
) -> Unit raise SshError {
  ignore(password)
  if self.kex.state != Done {
    raise ProtocolError("auth_password: key exchange is not complete")
  }
  raise NotEncrypted
}

///|
/// Authenticate with a public key.
pub fn Client::auth_publickey(
  self : Client,
  _key : Bytes,
  _signature : Bytes,
) -> Unit raise SshError {
  if self.kex.state != Done {
    raise ProtocolError("auth_publickey: key exchange is not complete")
  }
  raise NotEncrypted
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
  abort(
    "Client::exec: not yet implemented (v0.1 stub — see docs/prd_001.md §Step 4.5)",
  )
}

///|
/// Close the SSH connection cleanly (sends DISCONNECT if possible).
pub fn Client::close(self : Client) -> Unit {
  match self.conn {
    Connected(conn) => conn.close()
  }
}

// --- Internal helpers -----------------------------------------------

///|
fn read_line(conn : @socket.Tcp) -> String raise SshError {
  let line = conn.read_line() catch { e => raise IoError("read_line: \{e}") }
  strip_line_ending(line)
}

///|
fn Client::read_plain_packet(self : Client) -> Bytes raise SshError {
  match self.conn {
    Connected(conn) =>
      read_packet(
        size => {
          conn.read_exact(size) catch {
            e => raise IoError("read packet: \{e}")
          }
        },
        8,
        0,
        body => body,
        (_data, _mac) => (),
      )
  }
}

///|
fn Client::write_plain_packet(
  self : Client,
  payload : Bytes,
) -> Unit raise SshError {
  let packet = write_packet(payload, 8, false, _data => b"")
  match self.conn {
    Connected(conn) =>
      conn.write_bytes(packet) catch {
        e => raise IoError("write packet: \{e}")
      }
  }
}

///|
fn strip_line_ending(line : String) -> String {
  let arr = line.to_array()
  let mut end = arr.length()
  while end > 0 &&
        (arr.unsafe_get(end - 1) == '\n' || arr.unsafe_get(end - 1) == '\r') {
    end = end - 1
  }
  let sb = StringBuilder::new()
  for i in 0..<end {
    sb.write_char(arr.unsafe_get(i))
  }
  sb.to_string()
}
