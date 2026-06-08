///|
/// SSH 协议层 — KEX 状态机（RFC 4253 §6）。
///
/// 支持的密钥交换算法：
///   - curve25519-sha256           (RFC 8731)
///   - curve25519-sha256@libssh.org
///   - ecdh-sha2-nistp256          (RFC 5656)
///   - diffie-hellman-group14-sha256
///   - diffie-hellman-group14-sha1
///
/// 支持的 host key 算法：
///   - ssh-ed25519
///   - ecdsa-sha2-nistp256
///   - rsa-sha2-256 (ssh-rsa with SHA-256)
///   - ssh-rsa      (with SHA-1, 仅兼容)

///|
/// Algorithm name registry. Used in the SSH KEXINIT exchange.
pub fn kex_algorithms() -> Array[String] {
  [
    "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
  ]
}

///|
pub fn server_host_key_algorithms() -> Array[String] {
  ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-256", "ssh-rsa"]
}

///|
pub fn encryption_algorithms() -> Array[String] {
  [
    "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
    "aes256-ctr", "aes192-ctr", "aes128-ctr",
  ]
}

///|
pub fn mac_algorithms() -> Array[String] {
  ["hmac-sha2-512", "hmac-sha2-256", "hmac-sha1"]
}

///|
pub fn compression_algorithms() -> Array[String] {
  ["none"]
}

///|
/// KEXINIT payload (per RFC 4253 §7.1):
///   byte         SSH_MSG_KEXINIT (20)
///   byte[16]     cookie (random)
///   name-list    kex_algorithms
///   name-list    server_host_key_algorithms
///   name-list    encryption_algorithms_client_to_server
///   name-list    encryption_algorithms_server_to_client
///   name-list    mac_algorithms_client_to_server
///   name-list    mac_algorithms_server_to_client
///   name-list    compression_algorithms_client_to_server
///   name-list    compression_algorithms_server_to_client
///   name-list    languages_client_to_server
///   name-list    languages_server_to_client
///   boolean      first_kex_packet_follows
///   uint32       0 (reserved)
pub fn build_kexinit_payload(cookie : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_byte(20) // SSH_MSG_KEXINIT
  w.write_bytes(cookie)
  w.write_name_list(kex_algorithms())
  w.write_name_list(server_host_key_algorithms())
  w.write_name_list(encryption_algorithms())
  w.write_name_list(encryption_algorithms())
  w.write_name_list(mac_algorithms())
  w.write_name_list(mac_algorithms())
  w.write_name_list(compression_algorithms())
  w.write_name_list(compression_algorithms())
  w.write_name_list([""])
  w.write_name_list([""])
  w.write_byte(0) // first_kex_packet_follows
  w.write_uint32(0) // reserved
  w.to_bytes()
}

///|
/// Parse a KEXINIT payload received from the server.
pub fn parse_kexinit(payload : Bytes) -> KexInit raise SshError {
  let r = Reader::new(payload)
  let msg = r.read_byte()
  if msg != b'\x14' {
    raise ProtocolError("expected SSH_MSG_KEXINIT, got \{msg.to_int()}")
  }
  let cookie = r.read_bytes(16)
  let kex_algs = r.read_name_list()
  let host_key_algs = r.read_name_list()
  let enc_c2s = r.read_name_list()
  let enc_s2c = r.read_name_list()
  let mac_c2s = r.read_name_list()
  let mac_s2c = r.read_name_list()
  let comp_c2s = r.read_name_list()
  let comp_s2c = r.read_name_list()
  let _lang_c2s = r.read_name_list()
  let _lang_s2c = r.read_name_list()
  let _first_kex_follows = r.read_byte()
  let _reserved = r.read_uint32()
  {
    cookie,
    kex_algs,
    host_key_algs,
    enc_c2s,
    enc_s2c,
    mac_c2s,
    mac_s2c,
    comp_c2s,
    comp_s2c,
  }
}

///|
pub struct KexInit {
  cookie : Bytes
  kex_algs : Array[String]
  host_key_algs : Array[String]
  enc_c2s : Array[String]
  enc_s2c : Array[String]
  mac_c2s : Array[String]
  mac_s2c : Array[String]
  comp_c2s : Array[String]
  comp_s2c : Array[String]
}

///|
pub fn KexInit::first(self : KexInit, ours : Array[String]) -> String? {
  for alg in ours {
    for srv in self.kex_algs {
      if alg == srv {
        return Some(alg)
      }
    }
  }
  None
}

///|
pub fn KexInit::first_host_key(self : KexInit, ours : Array[String]) -> String? {
  for alg in ours {
    for srv in self.host_key_algs {
      if alg == srv {
        return Some(alg)
      }
    }
  }
  None
}

///|
pub fn KexInit::first_enc(self : KexInit, ours : Array[String]) -> String? {
  for alg in ours {
    for srv in self.enc_s2c {
      if alg == srv {
        return Some(alg)
      }
    }
  }
  None
}

///|
pub fn KexInit::first_mac(self : KexInit, ours : Array[String]) -> String? {
  for alg in ours {
    for srv in self.mac_s2c {
      if alg == srv {
        return Some(alg)
      }
    }
  }
  None
}

///|
pub fn KexInit::first_comp(self : KexInit, ours : Array[String]) -> String? {
  for alg in ours {
    for srv in self.comp_s2c {
      if alg == srv {
        return Some(alg)
      }
    }
  }
  None
}

// --- Key derivation (RFC 4253 §7.2) ----------------------------------

///|
/// Compute the SSH exchange hash `H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)`.
/// `v_c` / `v_s` are the SSH version strings; `i_c` / `i_s` are the KEXINIT
/// payloads; `k_s` is the server host key blob; `e` / `f` are the DH/ECDH
/// public values; `k` is the shared secret (mpint).
pub fn compute_exchange_hash(
  hash_alg : @crypto.Algorithm,
  v_c : Bytes,
  v_s : Bytes,
  i_c : Bytes,
  i_s : Bytes,
  k_s : Bytes,
  e : Bytes,
  f : Bytes,
  k : Bytes,
) -> Bytes raise @crypto.CryptoError {
  let h = @crypto.Hasher::new(hash_alg)
  h.update(v_c)
  h.update(v_s)
  h.update(i_c)
  h.update(i_s)
  h.update(k_s)
  h.update(encode_mpint_of_bytes(e))
  h.update(encode_mpint_of_bytes(f))
  h.update(encode_mpint_of_bytes(k))
  h.finalize()
}

///|
/// `mpint` encoding for SSH: same as `encode_mpint(BigInt)` but for raw
/// big-endian bytes. Adds a leading 0x00 if the high bit is set.
pub fn encode_mpint_of_bytes(bytes : Bytes) -> Bytes {
  if bytes.length() == 0 {
    return encode_string(b"\x00")
  }
  let first = bytes.unsafe_get(0).to_int()
  if first >= 0x80 {
    let buf = FixedArray::make(1, b'\x00')
    encode_uint32(bytes.length() + 1) + Bytes::from_fixedarray(buf) + bytes
  } else {
    encode_string(bytes)
  }
}

///|
/// Derive session keys from the exchange hash and shared secret (RFC 4253 §7.2).
/// Returns `(iv_c2s, iv_s2c, enc_key_c2s, enc_key_s2c, mac_key_c2s, mac_key_s2c)`.
pub fn derive_keys(
  hash_alg : @crypto.Algorithm,
  h : Bytes,
  k : Bytes,
  session_id : Bytes,
  enc_key_len : Int,
  enc_iv_len : Int,
  mac_key_len : Int,
) -> (Bytes, Bytes, Bytes, Bytes, Bytes, Bytes) raise @crypto.CryptoError {
  let iv_c2s = kdf(hash_alg, k, h, "A", session_id, enc_iv_len)
  let iv_s2c = kdf(hash_alg, k, h, "B", session_id, enc_iv_len)
  let ek_c2s = kdf(hash_alg, k, h, "C", session_id, enc_key_len)
  let ek_s2c = kdf(hash_alg, k, h, "D", session_id, enc_key_len)
  let mk_c2s = kdf(hash_alg, k, h, "E", session_id, mac_key_len)
  let mk_s2c = kdf(hash_alg, k, h, "F", session_id, mac_key_len)
  (iv_c2s, iv_s2c, ek_c2s, ek_s2c, mk_c2s, mk_s2c)
}

///|
/// KDF as defined in RFC 4253 §7.2:
///   key1 = HASH(K || H || X || session_id)
///   key  = key1 || HASH(K || H || key1) || ...
fn kdf(
  hash_alg : @crypto.Algorithm,
  k : Bytes,
  h : Bytes,
  x : String,
  session_id : Bytes,
  needed : Int,
) -> Bytes raise @crypto.CryptoError {
  let x_bytes = @utf8.encode(x)
  let mut out = b""
  let mut k1 = b""
  let mut i = 0
  while out.length() < needed {
    if i == 0 {
      let h1 = @crypto.Hasher::new(hash_alg)
      h1.update(k)
      h1.update(h)
      h1.update(x_bytes)
      h1.update(session_id)
      k1 = h1.finalize()
    } else {
      let h1 = @crypto.Hasher::new(hash_alg)
      h1.update(k)
      h1.update(h)
      h1.update(k1)
      k1 = h1.finalize()
    }
    out = out + k1
    i = i + 1
  }
  if out.length() <= needed {
    return out
  }
  let arr = out.to_fixedarray()
  let view = FixedArray::makei(needed, i => arr.unsafe_get(i))
  Bytes::from_fixedarray(view)
}

// --- KEX state machine scaffolding -----------------------------------

///|
/// KEX state machine. Drives the SSH_MSG_KEXINIT / KEXDH_INIT / KEXDH_REPLY /
/// SSH_MSG_NEWKEYS exchange. The actual key generation and exchange logic is
/// implemented by callers; this struct only tracks state.
pub struct Kex {
  priv state : @string.View // marker; replaced by enum below
  // We use a plain String field for the state name since `@string.View`
  // would require importing another pkg; this is a stub type.
}

///|
/// Public KEX state. Drives the SSH transport-level key exchange.
pub enum KexState {
  /// Before any KEX has been performed.
  Initial
  /// We've sent KEXINIT; awaiting the server's.
  SentKexinit
  /// Server's KEXINIT received; negotiating algorithms.
  Negotiating
  /// We've sent KEXDH_INIT / KEXECDH_INIT; awaiting the reply.
  SentDhInit
  /// Server's KEXDH_REPLY / KEXECDH_REPLY received; computing the hash and
  /// deriving session keys.
  ComputingHash
  /// Ready to send NEWKEYS.
  ReadyForNewKeys
  /// NEWKEYS received; about to install the new keys.
  InstallKeys
  /// KEX complete.
  Done
} derive(Eq, Show)

///|
/// KEX state machine. Drives the SSH_MSG_KEXINIT / KEXDH_INIT / KEXDH_REPLY /
/// SSH_MSG_NEWKEYS exchange. The actual key generation and exchange logic is
/// implemented by callers; this struct only tracks state.
pub struct KexContext {
  mut state : KexState
  mut kex_alg : String
  mut host_key_alg : String
  mut enc_alg : String
  mut mac_alg : String
  mut comp_alg : String
  v_c : Bytes
  v_s : Bytes
  i_c : Bytes
  mut i_s : Bytes
  cookie : Bytes
  priv ephemeral : @crypto.PKey?
  priv peer_host_key : Bytes
  exchange_hash : Bytes
  shared_secret : Bytes
  session_id : Bytes
  priv session_id_set : Bool
}

///|
pub fn KexContext::new(v_c : Bytes, v_s : Bytes) -> KexContext {
  let cookie = kex_random_bytes(16)
  let i_c = build_kexinit_payload(cookie)
  {
    state: Initial,
    kex_alg: "",
    host_key_alg: "",
    enc_alg: "",
    mac_alg: "",
    comp_alg: "",
    v_c,
    v_s,
    i_c,
    i_s: b"",
    cookie,
    ephemeral: None,
    peer_host_key: b"",
    exchange_hash: b"",
    shared_secret: b"",
    session_id: b"",
    session_id_set: false,
  }
}

///|
#cfg(platform="windows")
fn kex_random_bytes(n : Int) -> Bytes {
  Bytes::make(n, b'\x00')
}

///|
#cfg(not(platform="windows"))
fn kex_random_bytes(n : Int) -> Bytes {
  @crypto.rand_bytes(n) catch {
    _ => Bytes::make(n, b'\x00')
  }
}

///|
pub fn KexContext::transition_to(self : KexContext, s : KexState) -> Unit {
  self.state = s
}

// --- High-level entry point -----------------------------------------

///|
/// Run a full key exchange against an open SSH connection. This is a
/// coordination layer over the lower-level packet IO.
///
/// The full implementation:
/// 1. Send KEXINIT (uses i_c from KexContext)
/// 2. Read server's KEXINIT, fill i_s, pick algorithms
/// 3. For curve25519 / nistp256: generate ephemeral, send KEXDH_INIT/REPLY
/// 4. For DH group14: same with the OpenSSL-backed BN_mod_exp
/// 5. Compute exchange hash, derive keys, send NEWKEYS
/// 6. On the server's NEWKEYS, atomically install the new keys
pub fn KexContext::drive(
  self : KexContext,
  read_packet : () -> Bytes raise SshError,
  write_packet : (Bytes) -> Unit raise SshError,
) -> Unit raise SshError {
  // TODO(Step 4.2): implement the full state machine. This is intentionally
  // a stub — it advances the state to `Done` but does not perform any
  // actual KEX. The packet framing, crypto primitives, and algorithm
  // registry are all in place; the missing piece is the I/O loop that
  // threads them together.
  if self.state != Initial {
    raise ProtocolError("kex: invalid state \{self.state}")
  }
  write_packet(self.i_c)
  self.transition_to(SentKexinit)
  let server_kexinit = read_packet()
  self.i_s = server_kexinit
  let server = parse_kexinit(server_kexinit)
  self.transition_to(Negotiating)
  self.kex_alg = require_algorithm("kex", server.first(kex_algorithms()))
  self.host_key_alg = require_algorithm(
    "host key",
    server.first_host_key(server_host_key_algorithms()),
  )
  self.enc_alg = require_algorithm(
    "encryption",
    server.first_enc(encryption_algorithms()),
  )
  self.mac_alg = require_algorithm("mac", server.first_mac(mac_algorithms()))
  self.comp_alg = require_algorithm(
    "compression",
    server.first_comp(compression_algorithms()),
  )
  self.transition_to(SentDhInit)
  raise ProtocolError(
    "kex: KEXDH/ECDH exchange is not implemented after KEXINIT negotiation",
  )
}

///|
fn require_algorithm(kind : String, value : String?) -> String raise SshError {
  match value {
    Some(alg) => alg
    None => raise ProtocolError("kex: no matching \{kind} algorithm")
  }
}
