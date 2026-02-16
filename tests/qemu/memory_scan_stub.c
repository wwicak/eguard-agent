#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    const char *marker = "eguard-shellcode-marker";
    size_t len = strlen(marker) + 1;
    void *region = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        return 1;
    }
    memcpy(region, marker, len);
    sleep(30);
    return 0;
}
