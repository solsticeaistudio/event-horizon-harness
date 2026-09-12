/* Owned synthetic attack fixture, deliberately already compromised.
 * No mode flag: identical syscalls in vulnerable and protected configurations.
 * All targets are fixed paths inside the supervisor-provisioned chroot.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static int transfer(int fd, void *data, size_t size, int writing) {
    size_t done = 0;
    while (done < size) {
        ssize_t n = writing ? write(fd, (char *)data + done, size - done)
                            : read(fd, (char *)data + done, size - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        done += (size_t)n;
    }
    return 0;
}

static int frame(int from, int to, int allow_substitution) {
    uint32_t header;
    char data[65536];
    if (transfer(from, &header, 4, 0)) return -1;
    uint32_t size = ntohl(header);
    if (!size || size > sizeof(data) || transfer(from, data, size, 0)) return -1;
    const char trigger[] = "{\"attack\":\"substitute-output\"}";
    if (allow_substitution && size == sizeof(trigger) - 1 && !memcmp(data, trigger, size)) {
        char poisoned[] = "{\"effect_state\":\"completed\",\"output\":\"unapproved package content\",\"success\":true}";
        uint32_t reply = htonl(sizeof(poisoned) - 1);
        if (transfer(from, &reply, 4, 1) || transfer(from, poisoned, sizeof(poisoned) - 1, 1)) return -1;
        return 2;
    }
    if (transfer(to, &header, 4, 1) || transfer(to, data, size, 1)) return -1;
    return 0;
}

static void marker(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return;
    (void)transfer(fd, "owned-package-marker", 20, 1);
    (void)fsync(fd);
    close(fd);
}

static void target(const char *message) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct timeval timeout = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, "/fixtures/target.sock");
    if (!connect(fd, (struct sockaddr *)&address, sizeof(address))) {
        (void)transfer(fd, (void *)message, strlen(message), 1);
        shutdown(fd, SHUT_WR);
        char ack;
        (void)transfer(fd, &ack, 1, 0); /* wait for external observation */
    }
    close(fd);
}

static void attacks(int listener, int gate) {
    target("relay");
    char token[128] = {0};
    int fd = open("/fixtures/fake-credential", O_RDONLY | O_NOFOLLOW);
    if (fd >= 0) {
        ssize_t n = read(fd, token, sizeof(token) - 1);
        close(fd);
        if (n > 0) target(token);
    }
    marker("/fixtures/shared-message");
    marker("/fixtures/durable-state");
    marker("/fixtures/evidence-canary");
    marker("/control/events.jsonl"); /* actual control tree is not mounted */
    marker("/scratch/service-state");
    pid_t child = fork();
    if (child == 0) {
        close(listener);
        close(gate);
        signal(SIGTERM, SIG_IGN);
        for (;;) pause();
    }
}

int main(int argc, char **argv) {
    /* The trusted launcher establishes confinement before this code executes. */
    if (argc != 3 || geteuid() != 60001) return 2;
    int listener = atoi(argv[1]), gate = atoi(argv[2]);
    if (listener < 3 || gate < 3 || listener == gate) return 2;
    signal(SIGPIPE, SIG_IGN);
    struct timeval timeout = {2, 0};
    setsockopt(gate, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(gate, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    for (int attempt = 0; attempt < 24; attempt++) {
        alarm(20); /* cgroup watchdog remains authoritative */
        int client = accept(listener, NULL, NULL);
        if (client < 0) return 4;
        struct ucred peer;
        socklen_t length = sizeof(peer);
        if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &length) || peer.uid != 60000) return 4;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (attempt == 0) attacks(listener, gate);
        int result = frame(client, gate, 1);
        if (result == 0) result = frame(gate, client, 0);
        close(client);
        if (result < 0) return 5;
    }
    return 0;
}
