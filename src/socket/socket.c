/*
 * Socket FFI implementation for Windows (MinGW compatible)
 * Provides basic TCP socket functionality without async
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <moonbit.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

static int winsock_initialized = 0;

static int send_all(SOCKET sock, const char *buffer, int data_len) {
    int sent = 0;
    while (sent < data_len) {
        int result = send(sock, buffer + sent, data_len - sent, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        sent += result;
    }
    return sent;
}

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
    int result = send_all(sock, buffer, data_len);
    free(buffer);

    return result;
}

int socket_send_bytes(int handle, moonbit_bytes_t data, int data_len) {
    SOCKET sock = (SOCKET)handle;
    const char *buffer = (const char *)Moonbit_bytes_ptr(data);
    return send_all(sock, buffer, data_len);
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

static int send_all(int sock, const char *buffer, int data_len) {
    int sent = 0;
    while (sent < data_len) {
        int result = (int)send(sock, buffer + sent, (size_t)(data_len - sent), 0);
        if (result <= 0) {
            return -1;
        }
        sent += result;
    }
    return sent;
}

static char *moonbit_string_to_ascii(moonbit_string_t s, int *len_out) {
    int len = Moonbit_string_length(s);
    char *out = (char *)malloc((size_t)len + 1);
    if (!out) {
        return 0;
    }
    const uint16_t *src = (const uint16_t *)Moonbit_string_ptr(s);
    for (int i = 0; i < len; i++) {
        out[i] = (char)src[i];
    }
    out[len] = '\0';
    if (len_out) {
        *len_out = len;
    }
    return out;
}

int socket_init(void) {
    return 0;  // No initialization needed on Unix
}

int socket_create(void) {
    return socket(AF_INET, SOCK_STREAM, 0);
}

int socket_connect(int handle, moonbit_string_t host_str, int port) {
    int host_len = 0;
    char *host = moonbit_string_to_ascii(host_str, &host_len);
    (void)host_len;
    if (!host) {
        return -1;
    }

    char port_buf[16];
    snprintf(port_buf, sizeof(port_buf), "%d", port);

    struct addrinfo hints;
    struct addrinfo *result = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port_buf, &hints, &result);
    free(host);
    if (rc != 0) {
        return rc;
    }

    int connected = -1;
    for (struct addrinfo *rp = result; rp != 0; rp = rp->ai_next) {
        if (connect(handle, rp->ai_addr, rp->ai_addrlen) == 0) {
            connected = 0;
            break;
        }
    }
    freeaddrinfo(result);
    return connected;
}

int socket_send(int handle, moonbit_string_t data_str) {
    int data_len = 0;
    char *buffer = moonbit_string_to_ascii(data_str, &data_len);
    if (!buffer) {
        return -1;
    }
    int result = send_all(handle, buffer, data_len);
    free(buffer);
    return result;
}

int socket_send_bytes(int handle, moonbit_bytes_t data, int data_len) {
    const char *buffer = (const char *)Moonbit_bytes_ptr(data);
    return send_all(handle, buffer, data_len);
}

int socket_recv(int handle, moonbit_bytes_t buffer, int offset, int size) {
    uint8_t *buf_ptr = (uint8_t *)Moonbit_bytes_ptr(buffer);
    return (int)recv(handle, (char *)(buf_ptr + offset), (size_t)size, 0);
}

void socket_close(int handle) {
    close(handle);
}

#endif
