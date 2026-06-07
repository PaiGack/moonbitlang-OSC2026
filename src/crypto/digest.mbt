///|
/// SSH 协议层需要的 hash 算法包装。算法 id:
///   1 = SHA-1   (RFC 4253 §6.4; 仅 host key 旧兼容)
///   2 = SHA-256 (RFC 6668 / RFC 4253 kex)
///   3 = SHA-384
///   4 = SHA-512 (RFC 6668 SHA-512 算法族)

///|
pub enum Algorithm {
  Sha1 = 1
  Sha256 = 2
  Sha384 = 3
  Sha512 = 4
} derive(Eq, Show)

///|
pub fn Algorithm::output_len(self : Algorithm) -> Int {
  match self {
    Sha1 => 20
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
}

///|
pub fn Algorithm::block_len(self : Algorithm) -> Int {
  // 全部为 64 (SHA-1/256) 或 128 (SHA-384/512) — SSH 暂未用到此值
  match self {
    Sha1 | Sha256 => 64
    Sha384 | Sha512 => 128
  }
}

///|
/// C 侧约定的算法 id
fn alg_id(a : Algorithm) -> Int {
  match a {
    Sha1 => 1
    Sha256 => 2
    Sha384 => 3
    Sha512 => 4
  }
}

// --- FFI ------------------------------------------------------------

///|
#cfg(not(platform="windows"))
#borrow(ctx)
extern "C" fn md_ctx_new_ffi() -> @c_ffi_opaque = "moonbitlang_ssh_md_ctx_new"

///|
#cfg(not(platform="windows"))
extern "C" fn md_ctx_free_ffi(ctx : @c_ffi_opaque) = "moonbitlang_ssh_md_ctx_free"

///|
#cfg(not(platform="windows"))
extern "C" fn md_init_ffi(ctx : @c_ffi_opaque, alg : Int) -> Int = "moonbitlang_ssh_md_init"

///|
#cfg(not(platform="windows"))
#borrow(data)
extern "C" fn md_update_ffi(ctx : @c_ffi_opaque, data : Bytes, len : Int) -> Int = "moonbitlang_ssh_md_update"

///|
#cfg(not(platform="windows"))
#borrow(out)
extern "C" fn md_final_ffi(
  ctx : @c_ffi_opaque,
  out : FixedArray[Byte],
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_md_final"

///|
#cfg(not(platform="windows"))
#borrow(data)
extern "C" fn digest_oneshot_ffi(
  alg : Int,
  data : Bytes,
  len : Int,
  out : FixedArray[Byte],
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_digest"

///|
#cfg(not(platform="windows"))
extern "C" fn md_size_ffi(alg : Int) -> Int = "moonbitlang_ssh_md_size"

// --- Public API ----------------------------------------------------

///|
/// Incremental hasher. Use `update` repeatedly then `final` to get digest.
pub struct Hasher {
  priv ctx : @c_ffi_opaque
  priv alg : Algorithm
}

///|
pub fn Hasher::new(alg : Algorithm) -> Hasher {
  ensure_openssl()
  let ctx = md_ctx_new_ffi()
  if md_init_ffi(ctx, alg_id(alg)) != 1 {
    md_ctx_free_ffi(ctx)
    err_clear()
    raise CryptoError::OperationFailed("EVP_DigestInit_ex", err_get_error())
  }
  { ctx, alg }
}

///|
pub fn update(self : Hasher, data : Bytes) -> Unit {
  if md_update_ffi(self.ctx, data, data.length()) != 1 {
    err_clear()
    raise CryptoError::OperationFailed("EVP_DigestUpdate", err_get_error())
  }
}

///|
pub fn update_string(self : Hasher, s : String) -> Unit {
  let bytes = @utf8.encode(s)
  self.update(bytes)
}

///|
/// Finalize and return the digest. The hasher is consumed.
pub fn final(self : Hasher) -> Bytes {
  let out_len_ref = Ref(0)
  let out = FixedArray::make(self.alg.output_len(), b'\x00')
  let rc = md_final_ffi(self.ctx, out, out_len_ref)
  md_ctx_free_ffi(self.ctx)
  if rc != 1 || out_len_ref.val != self.alg.output_len() {
    err_clear()
    raise CryptoError::OperationFailed("EVP_DigestFinal_ex", err_get_error())
  }
  out.unsafe_reinterpret_as_bytes()
}

// --- One-shot ------------------------------------------------------

///|
/// Compute digest in a single call. Convenience over `Hasher`.
pub fn digest(alg : Algorithm, data : Bytes) -> Bytes {
  ensure_openssl()
  let out_len_ref = Ref(0)
  let out = FixedArray::make(alg.output_len(), b'\x00')
  let rc = digest_oneshot_ffi(alg_id(alg), data, data.length(), out, out_len_ref)
  if rc != 1 || out_len_ref.val != alg.output_len() {
    err_clear()
    raise CryptoError::OperationFailed("EVP_Digest", err_get_error())
  }
  out.unsafe_reinterpret_as_bytes()
}

///|
pub fn digest_string(alg : Algorithm, s : String) -> Bytes {
  digest(alg, @utf8.encode(s))
}
