/* Host stand-ins for the few kernel services the harnessed packages call: single-threaded
 * critical sections and heap. Everything else in the OS is compiled from the upstream tree. */
#include <stdlib.h>
#include "os/mynewt.h"

os_sr_t
os_arch_save_sr(void)
{
    return 0;
}

void
os_arch_restore_sr(os_sr_t sr)
{
    (void)sr;
}

int
os_arch_in_critical(void)
{
    return 0;
}

void *
os_malloc(size_t size)
{
    return malloc(size);
}

void
os_free(void *mem)
{
    free(mem);
}

void *
os_realloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

/* Scheduler entry points referenced by testutil's task helpers (TEST_CASE_TASK); the host
 * harnesses and self-tests never start the OS, so reaching one is a bug. */
#include <stdio.h>

static void
no_scheduler(const char *what)
{
    fprintf(stderr, "mayhem shim: %s needs the OS scheduler\n", what);
    abort();
}

void
os_init(int (*main_fn)(int argc, char **argv))
{
    (void)main_fn;
}

void
os_start(void)
{
    no_scheduler("os_start");
}

void
os_arch_os_stop(void)
{
    no_scheduler("os_arch_os_stop");
}

struct os_eventq *
os_eventq_dflt_get(void)
{
    no_scheduler("os_eventq_dflt_get");
    return NULL;
}

void
os_eventq_loop(struct os_eventq *evq)
{
    (void)evq;
    no_scheduler("os_eventq_loop");
}

int
os_task_init(struct os_task *t, const char *name, os_task_func_t func,
             void *arg, uint8_t prio, os_time_t sanity_itvl,
             os_stack_t *stack_bottom, uint16_t stack_size)
{
    (void)t; (void)name; (void)func; (void)arg; (void)prio;
    (void)sanity_itvl; (void)stack_bottom; (void)stack_size;
    no_scheduler("os_task_init");
    return -1;
}

void
os_eventq_put(struct os_eventq *evq, struct os_event *ev)
{
    (void)evq;
    (void)ev;
    no_scheduler("os_eventq_put");
}

void tu_init(void);
void os_msys_init(void);
void os_mempool_module_init(void);

void
mayhem_sysinit(void)
{
    tu_init();
    os_mempool_module_init();
    os_msys_init();
}
