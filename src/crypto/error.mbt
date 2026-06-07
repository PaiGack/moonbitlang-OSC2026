///|
/// Errors raised by the crypto FFI layer.
pub suberror CryptoError {
  /// `RAND_bytes` returned a non-success status.
  RandomFailed(String)
  /// A FFI call returned a non-success status (and no more specific cause
  /// applies). The string is the OpenSSL error queue.
  OperationFailed(String, String)
  /// An invalid argument was passed (e.g. unsupported algorithm id, NULL
  /// pointer to a function that requires a buffer).
  InvalidArgument(String)
  /// A buffer was too small to hold the output.
  BufferTooSmall(String)
  /// The caller asked for a feature not supported on the current build
  /// (e.g. Windows where the OpenSSL shim is not wired up).
  Unsupported(String)
} derive(Show, Eq)

///|
/// Render a `CryptoError` as a single human-readable line.
pub fn CryptoError::message(self : CryptoError) -> String {
  match self {
    RandomFailed(detail) => "crypto: RAND_bytes failed: \{detail}"
    OperationFailed(op, detail) => "crypto: \{op} failed: \{detail}"
    InvalidArgument(detail) => "crypto: invalid argument: \{detail}"
    BufferTooSmall(detail) => "crypto: buffer too small: \{detail}"
    Unsupported(detail) => "crypto: unsupported: \{detail}"
  }
}
