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

  // Target server from user
  let target = "cnb-rhf-1jq6phcqc-001.f2553f86-2076-4cdb-96a9-e266f083e387-b48@cnb.space"
  let host = "cnb.space"
  let port = 22

  println("Test Configuration:")
  println("  Target: \{target}")
  println("  Host: \{host}")
  println("  Port: \{port}")
  println("")

  // Attempt SSH connection
  match @SSH.connect(host, port) {
    Ok(conn) => {
      println("✓ SSH Connection object created successfully!")
      println("")
      println("Framework ready for:")
      println("  - SSH transport layer protocol")
      println("  - Key exchange (KEXINIT)")
      println("  - Password authentication")
      println("  - Channel management and exec")
      println("")
      println("Next steps:")
      println("  1. Add a TCP package dependency")
      println("  2. Implement actual network socket connection")
      println("  3. Complete Diffie-Hellman key exchange")
      println("  4. Add encryption (AES-CTR)")
      println("")
      println("This implementation provides the SSH protocol structure.")
    }
    Err(e) => {
      println("✗ Connection setup failed: \{e}")
    }
  }
}
