///|
test "KexContext::drive sends KEXINIT and negotiates algorithms" {
  let ctx = KexContext::new(b"SSH-2.0-test-client", b"SSH-2.0-test-server")
  let server_payload = build_kexinit_payload(Bytes::make(16, b'\x01'))
  let sent : Array[Bytes] = []
  try ctx.drive(() => server_payload, payload => sent.push(payload)) catch {
    ProtocolError(message) => {
      assert_true(message.contains("KEXDH/ECDH"))
    }
    _ => fail("expected protocol error after KEXINIT negotiation")
  } noraise {
    _ => fail("expected KEXDH/ECDH to remain unimplemented")
  }
  assert_eq(sent.length(), 1)
  assert_eq(sent[0], ctx.i_c)
  assert_eq(ctx.state, SentDhInit)
  assert_eq(ctx.kex_alg, "curve25519-sha256")
  assert_eq(ctx.host_key_alg, "ssh-ed25519")
  assert_eq(ctx.enc_alg, "chacha20-poly1305@openssh.com")
  assert_eq(ctx.mac_alg, "hmac-sha2-512")
  assert_eq(ctx.comp_alg, "none")
}
