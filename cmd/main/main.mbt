///|
/// Entry point for the SSH client CLI
/// Run with `moon run cmd/main` from the project root.
fn main {
  println("MoonBit SSH Client")
  println("==================")
  println("")
  println("This is a framework implementation of the SSH protocol in MoonBit.")
  println("The project is being developed for the MoonBit 2026 Open Source Competition.")
  println("")
  println("Note: Full SSH functionality requires native compilation with libssh2.")
  println("The wasm-gc target provides the protocol structure but not the network layer.")
  println("")
  println("Framework ready for:")
  println("  - SSH transport layer protocol")
  println("  - Key exchange (KEXINIT)")
  println("  - Password authentication")
  println("  - Channel management and exec")
}