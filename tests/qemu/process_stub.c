#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_pid(const char *path, pid_t pid) {
    FILE *file = fopen(path, "w");
    if (!file) {
        return;
    }
    fprintf(file, "%d", (int)pid);
    fclose(file);
}

int main(int argc, char **argv) {
    if (argc >= 6 && strcmp(argv[1], "--spawn") == 0) {
        const char *child1 = argv[2];
        const char *child2 = argv[3];
        const char *pid1_path = argv[4];
        const char *pid2_path = argv[5];

        pid_t first = fork();
        if (first == 0) {
            execl(child1, child1, "20", NULL);
            _exit(127);
        }

        pid_t second = fork();
        if (second == 0) {
            execl(child2, child2, "20", NULL);
            _exit(127);
        }

        if (first > 0) {
            write_pid(pid1_path, first);
        }
        if (second > 0) {
            write_pid(pid2_path, second);
        }

        sleep(25);
        return 0;
    }

    unsigned int secs = 20;
    if (argc > 1) {
        char *end = NULL;
        long parsed = strtol(argv[1], &end, 10);
        if (end && *end == '\0' && parsed > 0) {
            secs = (unsigned int)parsed;
        }
    }
    sleep(secs);
    return 0;
}
