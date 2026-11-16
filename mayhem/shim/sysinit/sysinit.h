#ifndef H_MAYHEM_SYSINIT
#define H_MAYHEM_SYSINIT
#include <assert.h>
void mayhem_sysinit(void);
#define SYSINIT_ASSERT_ACTIVE() do { } while (0)
#define SYSINIT_PANIC_ASSERT(x) assert(x)
/* newt's generated sysinit() runs each package's init; the self-tests need testutil's and msys's. */
#define sysinit() mayhem_sysinit()
#endif
