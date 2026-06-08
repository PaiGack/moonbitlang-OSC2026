///|
/// Simplified TCP socket implementation (stub for now)
/// This replaces moonbitlang/async/socket to avoid MSVC dependency

///|
/// A TCP connection
pub struct Tcp {
  host : String
  port : Int
}

///|
/// Connect to a remote host
pub fn Tcp::connect_to_host(host : String, ~port : Int) -> Tcp raise {
  // TODO: Implement real TCP connection
  // For now, this is a stub that just stores the connection info
  { host, port }
}

///|
/// Write data to the connection
pub fn Tcp::write(self : Tcp, data : String) -> Unit raise {
  // TODO: Implement real write
  ignore(self)
  ignore(data)
  raise IoError("TCP write not yet implemented")
}

///|
/// Read a line from the connection
pub fn Tcp::read_line(self : Tcp) -> String raise {
  // TODO: Implement real read
  ignore(self)
  raise IoError("TCP read not yet implemented")
}

///|
/// Close the connection
pub fn Tcp::close(self : Tcp) -> Unit {
  ignore(self)
  // TODO: Implement real close
}

///|
/// IO error type
pub suberror IoError {
  IoError(String)
} derive(Eq, Show)
