/* Fuzzes the base64 decoder (one-shot, bounded and chunked streaming) and the hex parser,
 * then round-trips whatever decoded cleanly through the matching encoder. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "os/mynewt.h"
#include "base64/base64.h"
#include "base64/hex.h"

static void
check(int ok)
{
    if (!ok) {
        abort();
    }
}

static int
base64_case(const char *str, size_t len)
{
    struct base64_decoder dec;
    uint8_t *out;
    char *enc;
    int dlen;
    int rc;

    dlen = base64_decode_len(str);
    out = malloc(dlen > 0 ? dlen : 1);
    check(out != NULL);
    rc = base64_decode(str, out);
    if (rc < 0) {
        free(out);
        return -1;
    }

    check(rc <= dlen);
    enc = malloc(BASE64_ENCODE_SIZE(rc > 0 ? rc : 1) + 1);
    check(enc != NULL);
    rc = base64_encode(out, rc, enc, 1);
    check(rc >= 0);
    {
        uint8_t *again = malloc(base64_decode_len(enc) + 1);
        int rc2;

        check(again != NULL);
        rc2 = base64_decode(enc, again);
        check(rc2 >= 0);
        free(again);
    }
    free(enc);
    free(out);

    /* Bounded decode into a deliberately small buffer, split across two calls. */
    memset(&dec, 0, sizeof(dec));
    out = malloc(8);
    check(out != NULL);
    dec.src = str;
    dec.src_len = len > 8 ? (int)(len / 2) : 0;
    dec.dst = out;
    dec.dst_len = 8;
    rc = base64_decoder_go(&dec);
    if (rc >= 0 && dec.src_len > 0) {
        dec.src = str + dec.src_len;
        dec.src_len = 0;
        dec.dst = out + rc;
        dec.dst_len = 8 - rc;
        if (dec.dst_len > 0) {
            (void)base64_decoder_go(&dec);
        }
    }
    free(out);
    return 0;
}

static int
hex_case(const char *str, size_t len)
{
    uint8_t out[32];
    char text[2 * sizeof(out) + 1];
    int rc;

    rc = hex_parse(str, (int)len, out, sizeof(out));
    if (rc < 0) {
        return -1;
    }
    check(rc <= (int)sizeof(out));
    check(hex_format(out, rc, text, sizeof(text)) != NULL);
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *copy;
    int rc;

    if (size < 2 || size > 2048) {
        return -1;
    }

    copy = malloc(size);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, data + 1, size - 1);
    copy[size - 2] = '\0';
    if (data[0] & 1) {
        rc = hex_case(copy, size - 2);
    } else {
        rc = base64_case(copy, size - 2);
    }
    free(copy);
    return rc;
}
