# parse_ip6_net(): off-by-one write in the address buffer

`util/parse/src/parse.c:234` accepts an address part of up to `MN_INET6_ADDRSTRLEN` (46) characters
(`slash - sval > MN_INET6_ADDRSTRLEN` is the rejection test), then copies it into `char buf[46]` and
writes the terminating NUL at `buf[slash - sval]` (`parse.c:242`). An address part of exactly 46
characters therefore writes `buf[46]`, one byte past the array (UBSan: `index 46 out of bounds for type
'char[46]'`; a stack write that ASan reports on some layouts).

Reproduce: `/mayhem/fuzz_parse-standalone repro` (46 `0` characters, then `/0`, as `parse_ip6_net`
input, selected by the harness's leading mode byte `0x05`).

Fix: reject with `>=`, i.e. `if (slash - sval >= MN_INET6_ADDRSTRLEN)`.
