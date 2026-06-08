/*
 * Socket FFI implementation for Windows (MinGW compatible)
 * Provides basic TCP socket functionality without async
 */

#include <stdint.h>
#include <string.h>
#include <moonbit.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

static int winsock_initialized = 0;

/*
 * Initialize Winsock2
 * Returns 0 on success, error code otherwise
 */
int socket_init(void) {
    if (winsock_initialized) {
        return 0;
    }

    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result == 0) {
        winsock_initialized = 1;
    }
    return result;
}

/*
 * Create a TCP socket
 * Returns socket handle on success, -1 on error
 */
int socket_create(void) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }
    return (int)sock;
}

/*
 * Connect to a remote host
 * Returns 0 on success, error code otherwise
 */
int socket_connect(int handle, moonbit_string_t host_str, int port) {
    // Extract host string from MoonBit string
    int host_len = Moonbit_string_length(host_str);
    char *host = (char *)malloc(host_len + 1);
    if (!host) {
        return -1;
    }

    // Copy string data (MoonBit strings are UTF-16 on Windows)
    const uint16_t *src = (const uint16_t *)Moonbit_string_ptr(host_str);
    for (int i = 0; i < host_len; i++) {
        host[i] = (char)src[i];  // Simple ASCII conversion
    }
    host[host_len] = '\0';

    // Setup address structure
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    // Convert hostname to IP address
    addr.sin_addr.s_addr = inet_addr(host);
    if (addr.sin_addr.s_addr == INADDR_NONE) {
        // Try resolving as hostname
        struct hostent *he = gethostbyname(host);
        free(host);
        if (!he) {
            return WSAGetLastError();
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    } else {
        free(host);
    }

    // Connect
    SOCKET sock = (SOCKET)handle;
    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (result == SOCKET_ERROR) {
        return WSAGetLastError();
    }

    return 0;
}

/*
 * Send data through socket
 * Returns number of bytes sent, or -1 on error
 */
int socket_send(int handle, moonbit_string_t data_str) {
    int data_len = Moonbit_string_length(data_str);
    const uint16_t *src = (const uint16_t *)Moonbit_string_ptr(data_str);

    // Convert to ASCII buffer
    char *buffer = (char *)malloc(data_len);
    if (!buffer) {
        return -1;
    }

    for (int i = 0; i < data_len; i++) {
        buffer[i] = (char)src[i];
    }

    SOCKET sock = (SOCKET)handle;
    int result = send(sock, buffer, data_len, 0);
    free(buffer);

    if (result == SOCKET_ERROR) {
        return -1;
    }

    return result;
}

/*
 * Receive data from socket
 * Returns number of bytes received, 0 on connection close, -1 on error
 */
int socket_recv(int handle, moonbit_bytes_t buffer, int offset, int size) {
    SOCKET sock = (SOCKET)handle;
    uint8_t *buf_ptr = (uint8_t *)Moonbit_bytes_ptr(buffer);

    int result = recv(sock, (char *)(buf_ptr + offset), size, 0);
    if (result == SOCKET_ERROR) {
        return -1;
    }

    return result;
}

/*
 * Close a socket
 */
void socket_close(int handle) {
    SOCKET sock = (SOCKET)handle;
    closesocket(sock);
}

#else
// Unix/Linux implementation placeholder
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

int socket_init(void) {
    return 0;  // No initialization needed on Unix
}

int socket_create(void) {
    return socket(AF_INET, SOCK_STREAM, 0);
}

int socket_connect(int handle, moonbit_string_t host_str, int port) {
    // TODO: Implement Unix version
    return -1;
}

int socket_send(int handle, moonbit_string_t data_str) {
    // TODO: Implement Unix version
    return -1;
}

int socket_recv(int handle, moonbit_bytes_t buffer, int offset, int size) {
    // TODO: Implement Unix version
    return -1;
}

void socket_close(int handle) {
    close(handle);
}

#endif
