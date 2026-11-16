/* Fuzzes the JSON object/array decoder (encoding/json) against a template that exercises every
 * attribute type: scalars, strings, enums and arrays of each element type, including arrays of objects. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "os/mynewt.h"
#include "json/json.h"

struct buf {
    struct json_buffer jb;
    const char *start;
    const char *end;
    size_t pos;
};

static char
buf_next(struct json_buffer *jb)
{
    struct buf *b = (struct buf *)jb;

    if (b->start + b->pos < b->end) {
        return b->start[b->pos++];
    }
    return '\0';
}

static char
buf_prev(struct json_buffer *jb)
{
    struct buf *b = (struct buf *)jb;

    if (b->pos > 0) {
        b->pos--;
        return b->start[b->pos];
    }
    return '\0';
}

static int
buf_readn(struct json_buffer *jb, char *dst, int n)
{
    struct buf *b = (struct buf *)jb;
    size_t rem = (size_t)(b->end - (b->start + b->pos));

    if (n < 0) {
        return 0;
    }
    if ((size_t)n > rem) {
        n = (int)rem;
    }
    memcpy(dst, b->start + b->pos, n);
    b->pos += n;
    return n;
}

struct sub {
    long long id;
    char name[8];
};

static const struct json_enum_t colors[] = {
    { "red", 1 }, { "green", 2 }, { "blue", 3 }, { NULL, 0 },
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    long long i64 = 0;
    unsigned long long u64 = 0;
    json_real_t real = 0;
    bool flag = false;
    char ch = 0;
    char str[16];
    char strs_store[64];
    char *strs[4];
    long long color = 0;
    long long ints[6];
    unsigned long long uints[4];
    bool bools[4];
    json_real_t reals[4];
    int n_ints = 0, n_uints = 0, n_bools = 0, n_reals = 0, n_strs = 0, n_subs = 0;
    struct sub subs[3];
    char *copy;
    struct buf b;
    int rc;

    if (size == 0 || size > 4096) {
        return -1;
    }

    const struct json_attr_t sub_attrs[] = {
        { .attribute = "id", .type = t_integer, .addr.offset = offsetof(struct sub, id),
          .nodefault = true },
        { .attribute = "name", .type = t_string, .addr.offset = offsetof(struct sub, name),
          .len = sizeof(subs[0].name), .nodefault = true },
        { .attribute = NULL },
    };
    const struct json_attr_t attrs[] = {
        { .attribute = "i", .type = t_integer, .addr.integer = &i64, .dflt.integer = 7 },
        { .attribute = "u", .type = t_uinteger, .addr.uinteger = &u64, .nodefault = true },
        { .attribute = "r", .type = t_real, .addr.real = &real, .nodefault = true },
        { .attribute = "b", .type = t_boolean, .addr.boolean = &flag, .nodefault = true },
        { .attribute = "c", .type = t_character, .addr.character = &ch, .nodefault = true },
        { .attribute = "s", .type = t_string, .addr.string = str, .len = sizeof(str),
          .nodefault = true },
        { .attribute = "color", .type = t_integer, .addr.integer = &color, .map = colors,
          .nodefault = true },
        { .attribute = "ia", .type = t_array,
          .addr.array = { .element_type = t_integer, .arr.integers.store = ints,
                          .maxlen = 6, .count = &n_ints },
          .nodefault = true },
        { .attribute = "ua", .type = t_array,
          .addr.array = { .element_type = t_uinteger, .arr.uintegers.store = uints,
                          .maxlen = 4, .count = &n_uints },
          .nodefault = true },
        { .attribute = "ba", .type = t_array,
          .addr.array = { .element_type = t_boolean, .arr.booleans.store = bools,
                          .maxlen = 4, .count = &n_bools },
          .nodefault = true },
        { .attribute = "ra", .type = t_array,
          .addr.array = { .element_type = t_real, .arr.reals.store = reals,
                          .maxlen = 4, .count = &n_reals },
          .nodefault = true },
        { .attribute = "sa", .type = t_array,
          .addr.array = { .element_type = t_string, .arr.strings.ptrs = strs,
                          .arr.strings.store = strs_store,
                          .arr.strings.storelen = sizeof(strs_store),
                          .maxlen = 4, .count = &n_strs },
          .nodefault = true },
        { .attribute = "oa", .type = t_array,
          .addr.array = { .element_type = t_structobject, .arr.objects.subtype = sub_attrs,
                          .arr.objects.base = (char *)subs,
                          .arr.objects.stride = sizeof(subs[0]),
                          .maxlen = 3, .count = &n_subs },
          .nodefault = true },
        { .attribute = "chk", .type = t_check, .dflt.check = "ok" },
        { .attribute = "ign", .type = t_ignore },
        { .attribute = NULL },
    };

    memset(subs, 0, sizeof(subs));
    memset(str, 0, sizeof(str));

    copy = malloc(size + 1);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, data, size);
    copy[size] = '\0';

    b.jb.jb_readn = buf_readn;
    b.jb.jb_read_next = buf_next;
    b.jb.jb_read_prev = buf_prev;
    b.start = copy;
    b.end = copy + size;
    b.pos = 0;

    rc = json_read_object(&b.jb, attrs);

    free(copy);
    return rc == 0 ? 0 : -1;
}
