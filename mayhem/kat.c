/* Known-answer probe over the fuzzed packages. Prints one line per check; mayhem/test.sh compares
 * the output to fixed expected values, so a neutered or broken library cannot pass. */
#include <stdio.h>
#include <string.h>
#include "os/mynewt.h"
#include "base64/base64.h"
#include "base64/hex.h"
#include "base62/base62.h"
#include "json/json.h"
#include "mn_socket/mn_socket.h"
#include "parse/parse.h"

struct jbuf {
    struct json_buffer jb;
    const char *s;
    size_t len;
    size_t pos;
};

static char
jb_next(struct json_buffer *jb)
{
    struct jbuf *b = (struct jbuf *)jb;

    return b->pos < b->len ? b->s[b->pos++] : '\0';
}

static char
jb_prev(struct json_buffer *jb)
{
    struct jbuf *b = (struct jbuf *)jb;

    return b->pos > 0 ? b->s[--b->pos] : '\0';
}

static int
jb_readn(struct json_buffer *jb, char *dst, int n)
{
    struct jbuf *b = (struct jbuf *)jb;

    if ((size_t)n > b->len - b->pos) {
        n = (int)(b->len - b->pos);
    }
    memcpy(dst, b->s + b->pos, n);
    b->pos += n;
    return n;
}

static const char *
status_name(int st)
{
    return st == 0 ? "ok" : st == SYS_ERANGE ? "erange" : st == SYS_EINVAL ? "einval" : "other";
}

int
main(void)
{
    uint8_t bin[32];
    char txt[96];
    unsigned int n;
    int st;
    int len;
    int i;

    i = base64_encode("Mayhem fuzz!", 12, txt, 1);
    printf("b64enc %d %s\n", i, txt);
    i = base64_encode("ab", 2, txt, 1);
    printf("b64enc %d %s\n", i, txt);
    i = base64_decode("TWF5aGVtIGZ1enoh", bin);
    printf("b64dec %d %.*s\n", i, i, bin);
    printf("b64declen %d\n", base64_decode_len("TWE="));
    printf("b64bad %d\n", base64_decode("TW*5", bin));

    i = hex_parse("DeadBeef01", 10, bin, sizeof(bin));
    hex_format(bin, i, txt, sizeof(txt));
    printf("hex %d %s\n", i, txt);

    n = sizeof(txt);
    i = base62_encode("\x01\x00", 2, txt, &n);
    printf("b62enc %d %.*s\n", i, (int)n, txt);
    n = sizeof(bin);
    i = base62_decode("4gfFC3", 6, bin, &n);
    printf("b62dec %d %u %02x%02x%02x%02x\n", i, n, bin[0], bin[1], bin[2], bin[3]);

    printf("ll %lld %s\n", parse_ll("-1234", &st), status_name(st));
    printf("ll %lld %s\n", parse_ll("0x1F", &st), status_name(st));
    printf("ll %lld %s\n", parse_ll("12x", &st), status_name(st));
    printf("ull %llu %s\n", parse_ull_bounds("300", 1, 255, &st), status_name(st));
    printf("bool %d %s\n", (int)parse_bool("TRUE", &st), status_name(st));
    printf("bool %d %s\n", (int)parse_bool("2", &st), status_name(st));

    st = parse_byte_stream_delim_base("de:ad:be:ef", ":", 16, sizeof(bin), bin, &len);
    printf("bytes %d %d %02x%02x%02x%02x\n", st, len, bin[0], bin[1], bin[2], bin[3]);

    {
        struct mn_in6_addr a6;
        struct mn_in_addr a4;
        uint8_t prefix;

        st = parse_ip6_net("fe80::1/64", &a6, &prefix);
        printf("ip6net %d %u %02x%02x...%02x\n", st, prefix, a6.s_addr[0], a6.s_addr[1],
               a6.s_addr[15]);
        printf("ip6net %d\n", parse_ip6_net("fe80::1/129", &a6, &prefix) != 0);
        st = mn_inet_pton(MN_AF_INET, "10.1.2.250", &a4);
        printf("pton4 %d %u.%u.%u.%u\n", st, ((uint8_t *)&a4)[0], ((uint8_t *)&a4)[1],
               ((uint8_t *)&a4)[2], ((uint8_t *)&a4)[3]);
        st = mn_inet_pton(MN_AF_INET6, "2001:db8::ff", &a6);
        mn_inet_ntop(MN_AF_INET6, &a6, txt, sizeof(txt));
        printf("pton6 %d %s\n", st, txt);
    }

    {
        static const char doc[] = "{\"n\": -42, \"ok\": true, \"s\": \"hi\", \"a\": [1, 2, 3]}";
        long long num = 0, arr[4] = { 0 };
        bool ok = false;
        char s[8] = "";
        int cnt = 0;
        struct jbuf jb = { { jb_readn, jb_next, jb_prev }, doc, sizeof(doc) - 1, 0 };
        const struct json_attr_t attrs[] = {
            { .attribute = "n", .type = t_integer, .addr.integer = &num, .nodefault = true },
            { .attribute = "ok", .type = t_boolean, .addr.boolean = &ok, .nodefault = true },
            { .attribute = "s", .type = t_string, .addr.string = s, .len = sizeof(s),
              .nodefault = true },
            { .attribute = "a", .type = t_array,
              .addr.array = { .element_type = t_integer, .arr.integers.store = arr,
                              .maxlen = 4, .count = &cnt },
              .nodefault = true },
            { .attribute = NULL },
        };

        st = json_read_object(&jb.jb, attrs);
        printf("json %d %lld %d %s %d %lld\n", st, num, ok, s, cnt, arr[0] + arr[1] + arr[2]);

        jb.s = "{\"zzz\": 1}";
        jb.len = strlen(jb.s);
        jb.pos = 0;
        printf("json-badattr %d\n", json_read_object(&jb.jb, attrs));
    }
    return 0;
}
