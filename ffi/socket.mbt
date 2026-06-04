// TCP Socket FFI declarations for MoonBit
// Provides basic TCP socket operations for SSH transport layer


pub type Socket  // TCP socket handle (C-managed lifetime)


pub enum SocketError {
  Success = 0
  CreateFailed = -1
  ConnectFailed = -2
  Timeout = -3
  SendFailed = -4
  ReceiveFailed = -5
  CloseFailed = -6
  InvalidSocket = -7
}


/// Create a new TCP socket
extern "c" fn socket_create() -> Socket = "moonbit_socket_create"


/// Connect socket to host:port
#borrow(host)
extern "c" fn socket_connect(socket : Socket, host : Bytes, port : Int) -> Int = "moonbit_socket_connect"


/// Send data on socket
extern "c" fn socket_send(socket : Socket, data : Bytes) -> Int = "moonbit_socket_send"


/// Receive data from socket (non-blocking, returns available data)
extern "c" fn socket_receive(socket : Socket, buffer : Bytes) -> Int = "moonbit_socket_receive"


/// Set socket to non-blocking mode
extern "c" fn socket_set_nonblocking(socket : Socket) -> Unit = "moonbit_socket_set_nonblocking"


/// Set socket to blocking mode
extern "c" fn socket_set_blocking(socket : Socket) -> Unit = "moonbit_socket_set_blocking"


/// Check if socket is connected
extern "c" fn socket_is_connected(socket : Socket) -> Int = "moonbit_socket_is_connected"


/// Close the socket
extern "c" fn socket_close(socket : Socket) -> Int = "moonbit_socket_close"


/// Get last socket error
extern "c" fn socket_get_error() -> Int = "moonbit_socket_get_error"


/// Get the raw file descriptor (for libssh2 handshake)
extern "c" fn socket_get_fd(socket : Socket) -> Int = "moonbit_socket_get_fd"