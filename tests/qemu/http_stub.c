#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static const char *kBody =
    "{\"policy_id\":\"\",\"config_version\":\"\",\"policy_json\":\"\"," 
    "\"certificate_policy\":null,\"commands\":[],\"versions\":[],"
    "\"fleet_baselines\":[],\"state\":{\"persistence_enabled\":false}}";

static void log_line(const char *line) {
    FILE *log = fopen("/tmp/server.log", "a");
    if (!log) {
        return;
    }
    fprintf(log, "%s\n", line);
    fclose(log);
}

static void handle_client(int client_fd) {
    char buffer[16384];
    size_t total = 0;
    ssize_t n = 0;
    char *header_end = NULL;

    while (total < sizeof(buffer) - 1) {
        n = recv(client_fd, buffer + total, sizeof(buffer) - 1 - total, 0);
        if (n <= 0) {
            break;
        }
        total += (size_t)n;
        buffer[total] = '\0';
        header_end = strstr(buffer, "\r\n\r\n");
        if (header_end != NULL) {
            break;
        }
    }

    if (total == 0) {
        return;
    }

    size_t header_len = total;
    if (header_end != NULL) {
        header_len = (size_t)(header_end - buffer) + 4;
    }

    char request_line[512];
    size_t line_len = 0;
    while (line_len < header_len && buffer[line_len] != '\n' && line_len < sizeof(request_line) - 1) {
        request_line[line_len] = buffer[line_len];
        line_len++;
    }
    while (line_len > 0 && (request_line[line_len - 1] == '\r' || request_line[line_len - 1] == '\n')) {
        line_len--;
    }
    request_line[line_len] = '\0';
    if (line_len > 0) {
        log_line(request_line);
    }

    size_t content_length = 0;
    char *cl = strstr(buffer, "content-length:");
    if (cl == NULL) {
        cl = strstr(buffer, "Content-Length:");
    }
    if (cl != NULL) {
        cl += strlen("content-length:");
        while (*cl == ' ' || *cl == '\t') {
            cl++;
        }
        content_length = (size_t)strtoul(cl, NULL, 10);
    }

    size_t body_read = total > header_len ? total - header_len : 0;
    while (body_read < content_length) {
        n = recv(client_fd, buffer, sizeof(buffer), 0);
        if (n <= 0) {
            break;
        }
        body_read += (size_t)n;
    }

    char response[2048];
    int response_len = snprintf(
        response,
        sizeof(response),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %zu\r\n\r\n%s",
        strlen(kBody),
        kBody);
    if (response_len > 0) {
        send(client_fd, response, (size_t)response_len, 0);
    }
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8081);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 16) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    for (;;) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            break;
        }
        handle_client(client_fd);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
