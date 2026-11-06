/* ABI probe: prints the host's real structure sizes and sysconf selectors.
 * build.rs turns these into Rust constants, and bionic.rs asserts them against
 * the glibc x86-64 layout this runtime claims to support. */
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    printf("PTHREAD_COND_SIZE=%zu\n", sizeof(pthread_cond_t));
    printf("PTHREAD_COND_ALIGN=%zu\n", _Alignof(pthread_cond_t));
    printf("PTHREAD_MUTEX_SIZE=%zu\n", sizeof(pthread_mutex_t));
    printf("PTHREAD_MUTEX_ALIGN=%zu\n", _Alignof(pthread_mutex_t));
    printf("PTHREAD_ATTR_SIZE=%zu\n", sizeof(pthread_attr_t));
    printf("SEM_SIZE=%zu\n", sizeof(sem_t));
    printf("SEM_ALIGN=%zu\n", _Alignof(sem_t));
    printf("SIGSET_SIZE=%zu\n", sizeof(sigset_t));
    printf("STAT_SIZE=%zu\n", sizeof(struct stat));
    printf("OFF_T_SIZE=%zu\n", sizeof(off_t));
    printf("LONG_SIZE=%zu\n", sizeof(long));
    printf("SC_PAGESIZE_SELECTOR=%d\n", _SC_PAGESIZE);
    printf("SC_NPROCESSORS_ONLN_SELECTOR=%d\n", _SC_NPROCESSORS_ONLN);
    printf("SC_PHYS_PAGES_SELECTOR=%d\n", _SC_PHYS_PAGES);
    printf("SC_OPEN_MAX_SELECTOR=%d\n", _SC_OPEN_MAX);
    printf("SC_CLK_TCK_SELECTOR=%d\n", _SC_CLK_TCK);
    printf("HOST_PAGESIZE=%ld\n", sysconf(_SC_PAGESIZE));
    printf("HOST_CLK_TCK=%ld\n", sysconf(_SC_CLK_TCK));
    printf("HOST_OPEN_MAX=%ld\n", sysconf(_SC_OPEN_MAX));
    return 0;
}
