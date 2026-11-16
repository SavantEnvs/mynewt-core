/*
 * mayhem/selftest/mn_socket_selftest.c — runs upstream's net/ip/mn_socket self-test cases that
 * exercise only the address converters (mn_inet_pton / mn_inet_ntop, the code fuzz_parse reaches).
 *
 * Upstream's own main (net/ip/mn_socket/selftest/src/mn_sock_test.c) also calls socket_tests, a
 * TEST_CASE_TASK that needs the OS scheduler and test_sem; the mayhem OS shim aborts on any scheduler
 * call, so that case is left out. The pre-test callback is copied verbatim from upstream's
 * mn_socket_test_init so the three cases run exactly as they do there.
 */
#include <stdio.h>
#include <string.h>

#include "os/mynewt.h"
#include "testutil/testutil.h"

#include "mn_socket/mn_socket.h"

#define MB_CNT 10
#define MB_SZ  512
static uint8_t test_mbuf_area[MB_CNT * MB_SZ];
static struct os_mempool test_mbuf_mpool;
static struct os_mbuf_pool test_mbuf_pool;

TEST_CASE_DECL(inet_pton_test)
TEST_CASE_DECL(inet6_pton_test)
TEST_CASE_DECL(inet_ntop_test)

static void
mn_socket_test_init(void *arg)
{
    int rc;

    rc = os_mempool_init(&test_mbuf_mpool, MB_CNT, MB_SZ,
                         test_mbuf_area, "mb");
    TEST_ASSERT_FATAL(rc == 0);

    rc = os_mbuf_pool_init(&test_mbuf_pool, &test_mbuf_mpool,
                           MB_CNT, MB_CNT);
    TEST_ASSERT_FATAL(rc == 0);

    rc = os_msys_register(&test_mbuf_pool);
    TEST_ASSERT_FATAL(rc == 0);
}

TEST_SUITE(mn_socket_selftest)
{
    tu_suite_set_pre_test_cb(mn_socket_test_init, NULL);

    inet_pton_test();
    inet6_pton_test();
    inet_ntop_test();
}

int
main(int argc, char **argv)
{
    mn_socket_selftest();
    return tu_any_failed;
}
