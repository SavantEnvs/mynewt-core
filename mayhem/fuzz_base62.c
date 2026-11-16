/* Fuzzes base62 decode of arbitrary text, and round-trips arbitrary bytes through encode/decode. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "os/mynewt.h"
#include "base62/base62.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    unsigned int out_size;
    uint8_t *out;
    int rc;

    if (size < 2 || size > 1024) {
        return -1;
    }

    if (data[0] & 1) {
        out_size = (unsigned int)size * 2;
        out = malloc(out_size);
        if (out == NULL) {
            return -1;
        }
        rc = base62_decode((const char *)data + 1, (unsigned int)size - 1, out, &out_size);
        free(out);
        return rc == BASE62_DECODE_OK ? 0 : -1;
    } else {
        unsigned int in_size = (unsigned int)size - 1;
        char *enc;
        uint8_t *dec;
        unsigned int enc_size;
        unsigned int dec_size;

        enc_size = in_size * 2 + 8;
        enc = malloc(enc_size);
        dec = malloc(enc_size);
        if (enc == NULL || dec == NULL) {
            free(enc);
            free(dec);
            return -1;
        }
        rc = base62_encode(data + 1, in_size, enc, &enc_size);
        if (rc != BASE62_DECODE_OK) {
            free(enc);
            free(dec);
            return -1;
        }
        dec_size = in_size * 2 + 8;
        rc = base62_decode(enc, enc_size, dec, &dec_size);
        if (rc != BASE62_DECODE_OK) {
            abort();
        }
        free(enc);
        free(dec);
        return 0;
    }
}
