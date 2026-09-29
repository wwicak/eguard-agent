/* Unprivileged CO-RE relocation regression against an actual Linux 5.4 BTF.
 * Link with the already-vendored libbpf archive; no kernel attachment needed. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <bpf/btf.h>
#include "relo_core.h"

struct ext_header {
    __u16 magic;
    __u8 version, flags;
    __u32 hdr_len, func_off, func_len, line_off, line_len, core_off, core_len;
};

int main(int argc, char **argv)
{
    assert(argc == 3);
    struct btf_ext *ext = NULL;
    struct btf *local = btf__parse_elf(argv[1], &ext);
    struct btf *target = btf__parse(argv[2], NULL);
    assert(local && target && ext);
    int task_id = btf__find_by_name_kind(target, "task_struct", BTF_KIND_STRUCT);
    assert(task_id > 0);
    __u32 size;
    const struct ext_header *hdr = btf_ext__raw_data(ext, &size);
    assert(hdr->hdr_len >= sizeof(*hdr) && hdr->core_len > 0);
    const char *cursor = (const char *)hdr + hdr->hdr_len + hdr->core_off;
    const char *end = cursor + hdr->core_len;
    __u32 record_size;
    memcpy(&record_size, cursor, 4);
    cursor += 4;
    assert(record_size >= sizeof(struct bpf_core_relo));
    unsigned exists = 0, legacy = 0, absent = 0;
    while (cursor < end) {
        __u32 count;
        memcpy(&count, cursor + 4, 4);
        cursor += 8;
        for (__u32 i = 0; i < count; i++, cursor += record_size) {
            const struct bpf_core_relo *relo = (const void *)cursor;
            struct bpf_core_spec specs[3] = {0};
            assert(bpf_core_parse_spec("generation", local, relo, &specs[0]) == 0);
            if (specs[0].len != 2 || !specs[0].spec[1].name)
                continue;
            const char *field = specs[0].spec[1].name;
            bool modern = strcmp(field, "start_boottime") == 0;
            bool old = strcmp(field, "real_start_time") == 0;
            if (!modern && !old)
                continue;
            struct bpf_core_cand candidate = { .btf = target, .id = task_id };
            struct bpf_core_cand_list candidates = { .cands = &candidate, .len = 1 };
            struct bpf_core_relo_res result = {0};
            assert(bpf_core_calc_relo_insn("generation", relo, i, local,
                                         &candidates, specs, &result) == 0);
            if (modern && relo->kind == BPF_CORE_FIELD_EXISTS) {
                assert(!result.poison && result.new_val == 0);
                exists++;
            } else if (modern && relo->kind == BPF_CORE_FIELD_BYTE_OFFSET) {
                assert(result.poison); /* Must be behind the existence guard. */
                absent++;
            } else if (old && relo->kind == BPF_CORE_FIELD_BYTE_OFFSET) {
                assert(!result.poison && result.new_val > 0);
                legacy++;
            }
        }
    }
    assert(exists > 0 && legacy > 0 && absent > 0);
    printf("%s: Linux 5.4 existence guards=%u legacy reads=%u absent reads=%u\n",
           argv[1], exists, legacy, absent);
    btf_ext__free(ext);
    btf__free(local);
    btf__free(target);
    return 0;
}
