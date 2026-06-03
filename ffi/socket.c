// TCP Socket FFI stubs for MoonBit
// Provides basic TCP socket operations using Winsock

#include <moonbit.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

typedef SOCKET SocketHandle;
#define SOCKET_INVALID INVALID_SOCKET
#define SOCKET_ERROR_CODE WSAGetLastError()
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

typedef int SocketHandle;
#define SOCKET_INVALID -1
#define SOCKET_ERROR_CODE errno
#endif

#include <string.h>
#include <stdlib.h>

static int socket_initialized = 0;

static void ensure_init(void) {
    if (!socket_initialized) {
#ifdef _WIN32
        WSADATA wsa_data;
        WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
        socket_initialized = 1;
    }
}

static void socket_destroy(void *ptr) {
    if (ptr) {
        SocketHandle *sock = (SocketHandle *)ptr;
        if (*sock != SOCKET_INVALID) {
#ifdef _WIN32
            closesocket(*sock);
#else
            close(*sock);
#endif
        }
    }
}

MOONBIT_FFI_EXPORT
void *moonbit_socket_create(void) {
    ensure_init();

    SocketHandle sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == SOCKET_INVALID) {
        return NULL;
    }

    SocketHandle *sock_ptr = (SocketHandle *)moonbit_make_external_object(
        socket_destroy, sizeof(SocketHandle));
    *sock_ptr = sock;

    return sock_ptr;
}

MOONBIT_FFI_EXPORT
int32_t moonbit_socket_connect(void *socket_ptr, moonbit_bytes_t host, int32_t port) {
    if (!socket_ptr) return -1;
    SocketHandle *sock_ptr = (SocketHandle *)socket_ptr;
    SocketHandle sock = *sock_ptr;

    if (sock == SOCKET_INVALID) return -7; // InvalidSocket

    const char *host_str = (const char *)host;
    int32_t host_len = Moonbit_array_length(host);

    char *host_cstr = (char *)malloc(host_len + 1);
    if (!host_cstr) return -3; // ALLOC_ERROR
    memcpy(host_cstr, host_str, host_len);
    host_cstr[host_len] = '\0';

    struct hostent *he = gethostbyname(host_cstr);
    free(host_cstr);

    if (!he) return -2; // ConnectFailed

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr = *(struct in_addr *)he->h_addr;

    memset(&(addr.sin_zero), 0, 8);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1) {
        return -2; // ConnectFailed
    }

    return 0; // Success
}

MOONBIT_FFI_EXPORT
int32_t moonbit_socket_send(void *socket_ptr, moonbit_bytes_t data) {
    if (!socket_ptr) return -1;
    SocketHandle *sock_ptr = (SocketHandle *)socket_ptr;
    SocketHandle sock = *sock_ptr;

    if (sock == SOCKET_INVALID) return -7; // InvalidSocket

    int32_t len = Moonbit_array_length(data);
    if (len == 0) return 0;

    int32_t sent = send(sock, (const char *)data, len, 0);
    if (sent == -1) return -4; // SendFailed

    return sent;
}

MOONBIT_FFI_EXPORT
int32_t moonbit_socket_receive(void *socket_ptr, moonbit_bytes_t buffer) {
    if (!socket_ptr) return -1;
    SocketHandle *sock_ptr = (SocketHandle *)socket_ptr;
    SocketHandle sock = *sock_ptr;

    if (sock == SOCKET_INVALID) return -7; // InvalidSocket

    int32_t buf_len = Moonbit_array_length(buffer);
    if (buf_len == 0) return 0;

    int32_t received = recv(sock, (char *)buffer, buf_len, 0);
    if (received == -1) return -5; // ReceiveFailed

    return received;
}

MOONBIT_FFI_EXPORT
void moonbit_socket_set_nonblocking(void *socket_ptr) {
    if (!socket_ptr) return;
    SocketHandle *sock_ptr = (SocketHandle *)socket_ptr;
    SocketHandle sock = *sock_ptr;

    if (sock == SOCKET_INVALID) return;

#ifdef _WIN32
    unsigned long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

MOONBIT_FFI_EXPORT
void moonbit_socket_set_blocking(void *socket_ptr) {
    if (!socket_ptr) return;
    SocketHandle *sock_ptr = (SocketHandle *)socket_ptr;
    SocketHandle sock = *sock_ptr;

    if (sock == SOCKET_INVALID) return;

#ifdef _WIN32
    unsigned long mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

MOONBIT_FFI_EXPORT
int32_t moonbit_socket_is_connected(void *socket_ptr) {
    if (!socket_ptr) return 0;
    SocketHandle *sock_ptr = (SocketHandle *)socket_ptr;
    SocketHandle sock = *sock_ptr;

    if (sock == SOCKET_INVALID) return 0;

    char tmp;
    int result = recv(sock, &tmp, 1, MSG_PEEK);
    if (result == 0) return 0; // Connection closed
    if (result == -1) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return 1; // Would block, still connected
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 1;
#endif
        return 0;
    }
    return 1;
}

MOONBIT_FFI_EXPORT
int32_t moonbit_socket_close(void *socket_ptr) {
    if (!socket_ptr) return -1;
    SocketHandle *sock_ptr = (SocketHandle *)socket_ptr;
    SocketHandle sock = *sock_ptr;

    if (sock == SOCKET_INVALID) return -7; // InvalidSocket

#ifdef _WIN32
    int result = closesocket(sock);
#else
    int result = close(sock);
#endif

    *sock_ptr = SOCKET_INVALID;

    return result == 0 ? 0 : -6; // CloseFailed or Success
}

MOONBIT_FFI_EXPORT
int32_t moonbit_socket_get_error(void) {
    return SOCKET_ERROR_CODE;
}

MOONBIT_FFI_EXPORT
int32_t moonbit_socket_get_fd(void *socket_ptr) {
    if (!socket_ptr) return -1;
    SocketHandle *sock_ptr = (SocketHandle *)socket_ptr;
    SocketHandle sock = *sock_ptr;

    if (sock == SOCKET_INVALID) return -7; // InvalidSocket

    return (int32_t)sock;
}