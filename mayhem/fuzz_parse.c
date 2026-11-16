/* Fuzzes util/parse (numeric, boolean, byte-stream and IPv6 prefix parsers) and the
 * mn_inet_pton/ntop address converters it builds on. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "os/mynewt.h"
#include "mn_socket/mn_socket.h"
#include "parse/parse.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t bytes[16];
    char text[MN_INET6_ADDRSTRLEN];
    struct mn_in6_addr a6;
    struct mn_in_addr a4;
    uint8_t prefix;
    char *str;
    int status;
    int len;
    int rc = 0;

    if (size < 2 || size > 512) {
        return -1;
    }

    str = malloc(size);
    if (str == NULL) {
        return -1;
    }
    memcpy(str, data + 1, size - 1);
    str[size - 2] = '\0';

    switch (data[0] % 8) {
    case 0:
        (void)parse_ll(str, &status);
        (void)parse_ll_bounds(str, -1000, 1000, &status);
        rc = status ? -1 : 0;
        break;
    case 1:
        (void)parse_ull(str, &status);
        (void)parse_ull_bounds(str, 1, 255, &status);
        rc = status ? -1 : 0;
        break;
    case 2:
        (void)parse_bool(str, &status);
        rc = status ? -1 : 0;
        break;
    case 3:
        rc = parse_byte_stream(str, sizeof(bytes), bytes, &len);
        break;
    case 4:
        rc = parse_byte_stream_delim_base(str, ":-", 16, sizeof(bytes), bytes, &len);
        if (rc != 0) {
            rc = parse_byte_stream_delim_base(str, ",", 10, sizeof(bytes), bytes, &len);
        }
        if (rc != 0) {
            rc = parse_byte_stream_exact_length(str, bytes, 6);
        }
        break;
    case 5:
        rc = parse_ip6_net(str, &a6, &prefix) == 0 ? 0 : -1;
        break;
    case 6:
        if (mn_inet_pton(MN_AF_INET6, str, &a6) == 1) {
            if (mn_inet_ntop(MN_AF_INET6, &a6, text, sizeof(text)) == NULL) {
                abort();
            }
            if (mn_inet_pton(MN_AF_INET6, text, &a6) != 1) {
                abort();
            }
        } else {
            rc = -1;
        }
        break;
    default:
        if (mn_inet_pton(MN_AF_INET, str, &a4) == 1) {
            if (mn_inet_ntop(MN_AF_INET, &a4, text, sizeof(text)) == NULL) {
                abort();
            }
        } else {
            rc = -1;
        }
        break;
    }

    free(str);
    return rc;
}
