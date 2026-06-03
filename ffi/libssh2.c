// libssh2 FFI stubs for MoonBit
// These stubs wrap libssh2 C library functions

#include <moonbit.h>
#include <libssh2.h>
#include <stdlib.h>
#include <string.h>

// Error mapping helper
static int map_libssh2_error(LIBSSH2_ERROR code) {
    return (int)code;
}

// Allocate external object for Session
static void session_destroy(void *ptr) {
    if (ptr) {
        LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)ptr;
        if (session) {
            libssh2_session_free(session);
        }
    }
}

// Allocate external object for Channel
static void channel_destroy(void *ptr) {
    if (ptr) {
        LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL *)ptr;
        if (channel) {
            libssh2_channel_free(channel);
        }
    }
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_init(int32_t flags) {
    return libssh2_init(flags);
}

MOONBIT_FFI_EXPORT
void moonbit_libssh2_exit(void) {
    libssh2_exit();
}

MOONBIT_FFI_EXPORT
void *moonbit_libssh2_session_init(void) {
    LIBSSH2_SESSION *session = libssh2_session_init();
    if (!session) {
        return NULL;
    }
    return moonbit_make_external_object(session_destroy, sizeof(LIBSSH2_SESSION *));
}

MOONBIT_FFI_EXPORT
void moonbit_libssh2_session_set_blocking(void *session_ptr, int32_t blocking) {
    if (!session_ptr) return;
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)session_ptr;
    libssh2_session_set_blocking(session, blocking);
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_session_handshake(void *session_ptr, int32_t socket_fd) {
    if (!session_ptr) return -1;
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)session_ptr;
    return libssh2_session_handshake(session, socket_fd);
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_userauth_password(void *session_ptr, moonbit_bytes_t username, moonbit_bytes_t password) {
    if (!session_ptr) return -1;
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)session_ptr;

    const char *user = (const char *)username;
    const char *pass = (const char *)password;
    int32_t user_len = Moonbit_array_length(username);
    int32_t pass_len = Moonbit_array_length(password);

    // Create null-terminated strings for C
    char *user_str = (char *)malloc(user_len + 1);
    char *pass_str = (char *)malloc(pass_len + 1);
    if (!user_str || !pass_str) {
        if (user_str) free(user_str);
        if (pass_str) free(pass_str);
        return -3; // ALLOC_ERROR
    }
    memcpy(user_str, user, user_len);
    user_str[user_len] = '\0';
    memcpy(pass_str, pass, pass_len);
    pass_str[pass_len] = '\0';

    int result = libssh2_userauth_password(session, user_str, pass_str);

    free(user_str);
    free(pass_str);

    return result;
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_userauth_publickey(void *session_ptr, moonbit_bytes_t username, moonbit_bytes_t public_key, moonbit_bytes_t private_key) {
    if (!session_ptr) return -1;
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)session_ptr;

    const char *user = (const char *)username;
    const char *pub_key = (const char *)public_key;
    const char *priv_key = (const char *)private_key;

    return libssh2_userauth_publickey(session, user, pub_key, private_key);
}

MOONBIT_FFI_EXPORT
void *moonbit_libssh2_channel_open(void *session_ptr) {
    if (!session_ptr) return NULL;
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)session_ptr;

    LIBSSH2_CHANNEL *channel = libssh2_channel_open(session);
    if (!channel) {
        return NULL;
    }

    return moonbit_make_external_object(channel_destroy, sizeof(LIBSSH2_CHANNEL *));
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_channel_exec(void *channel_ptr, moonbit_bytes_t command) {
    if (!channel_ptr) return -1;
    LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL *)channel_ptr;

    const char *cmd = (const char *)command;
    int32_t cmd_len = Moonbit_array_length(command);

    char *cmd_str = (char *)malloc(cmd_len + 1);
    if (!cmd_str) return -3; // ALLOC_ERROR
    memcpy(cmd_str, cmd, cmd_len);
    cmd_str[cmd_len] = '\0';

    int result = libssh2_channel_exec(channel, cmd_str);
    free(cmd_str);

    return result;
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_channel_read(void *channel_ptr, moonbit_bytes_t buffer) {
    if (!channel_ptr) return -1;
    LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL *)channel_ptr;

    return libssh2_channel_read(channel, (char *)buffer, Moonbit_array_length(buffer));
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_channel_read_stderr(void *channel_ptr, moonbit_bytes_t buffer) {
    if (!channel_ptr) return -1;
    LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL *)channel_ptr;

    return libssh2_channel_read_stderr(channel, (char *)buffer, Moonbit_array_length(buffer));
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_channel_send_eof(void *channel_ptr) {
    if (!channel_ptr) return -1;
    LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL *)channel_ptr;
    return libssh2_channel_send_eof(channel);
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_channel_close(void *channel_ptr) {
    if (!channel_ptr) return -1;
    LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL *)channel_ptr;
    return libssh2_channel_close(channel);
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_channel_free(void *channel_ptr) {
    if (!channel_ptr) return -1;
    LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL *)channel_ptr;
    return libssh2_channel_free(channel);
}

MOONBIT_FFI_EXPORT
moonbit_bytes_t moonbit_libssh2_session_last_error(void *session_ptr) {
    if (!session_ptr) {
        return moonbit_make_bytes(0, 0);
    }
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)session_ptr;
    char *err_msg = NULL;
    int err_len = 0;
    libssh2_session_last_error(session, &err_msg, &err_len, 0);

    if (!err_msg || err_len == 0) {
        return moonbit_make_bytes(0, 0);
    }

    moonbit_bytes_t result = moonbit_make_bytes(err_len, 0);
    memcpy(result, err_msg, err_len);
    return result;
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_session_is_authenticated(void *session_ptr) {
    if (!session_ptr) return 0;
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)session_ptr;
    return libssh2_session_is_connected(session) ? 1 : 0;
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_session_free(void *session_ptr) {
    if (!session_ptr) return -1;
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)session_ptr;
    return libssh2_session_free(session);
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_session_last_errno(void *session_ptr) {
    if (!session_ptr) return -1;
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)session_ptr;
    return libssh2_session_last_errno(session);
}

MOONBIT_FFI_EXPORT
void *moonbit_libssh2_channel_open_direct(void *session_ptr, moonbit_bytes_t host, int32_t port) {
    if (!session_ptr) return NULL;
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)session_ptr;

    const char *host_str = (const char *)host;
    int32_t host_len = Moonbit_array_length(host);

    char *host_cstr = (char *)malloc(host_len + 1);
    if (!host_cstr) return NULL;
    memcpy(host_cstr, host_str, host_len);
    host_cstr[host_len] = '\0';

    LIBSSH2_CHANNEL *channel = libssh2_channel_open_direct(session, host_cstr, port);
    free(host_cstr);

    if (!channel) {
        return NULL;
    }

    return moonbit_make_external_object(channel_destroy, sizeof(LIBSSH2_CHANNEL *));
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_channel_request_pty(void *channel_ptr, moonbit_bytes_t terminal) {
    if (!channel_ptr) return -1;
    LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL *)channel_ptr;

    const char *term = (const char *)terminal;
    int32_t term_len = Moonbit_array_length(terminal);

    char *term_str = (char *)malloc(term_len + 1);
    if (!term_str) return -3;
    memcpy(term_str, term, term_len);
    term_str[term_len] = '\0';

    int result = libssh2_channel_request_pty(channel, term_str);
    free(term_str);

    return result;
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_channel_request_pty_shell(void *channel_ptr) {
    if (!channel_ptr) return -1;
    LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL *)channel_ptr;
    return libssh2_channel_request_pty_shell(channel);
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_channel_get_exit_status(void *channel_ptr) {
    if (!channel_ptr) return -1;
    LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL *)channel_ptr;
    return libssh2_channel_get_exit_status(channel);
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_channel_eof(void *channel_ptr) {
    if (!channel_ptr) return -1;
    LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL *)channel_ptr;
    return libssh2_channel_eof(channel);
}

MOONBIT_FFI_EXPORT
int32_t moonbit_libssh2_channel_is_closed(void *channel_ptr) {
    if (!channel_ptr) return -1;
    LIBSSH2_CHANNEL *channel = (LIBSSH2_CHANNEL *)channel_ptr;
    return libssh2_channel_is_closed(channel);
}