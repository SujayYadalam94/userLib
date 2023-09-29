#include <emmintrin.h>
#include <stdatomic.h>

typedef struct {
    volatile int locked;
} bypassd_spinlock_t;

static inline void bypassd_pause() {
    _mm_pause();
}

static inline void bypassd_wait_until_equal(volatile uint32_t *addr, uint32_t expected,
        int memorder) {
    while (__atomic_load_n(addr, memorder) != expected)
        bypassd_pause();
}

static inline void bypassd_spinlock_init(bypassd_spinlock_t *l) {
    l->locked = 0;
}

static inline void bypassd_spinlock_lock(bypassd_spinlock_t *l) {
    int exp = 0;
    while (!__atomic_compare_exchange_n(&l->locked, &exp, 1, 0,
                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
       bypassd_wait_until_equal((volatile uint32_t *)&l->locked, 0,
                __ATOMIC_RELAXED);
        exp = 0;
    }
}

static inline int bypassd_spinlock_trylock(bypassd_spinlock_t *l) {
    int exp = 0;
    return __atomic_compare_exchange_n(&l->locked, &exp, 1, 0,
                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static inline void bypassd_spinlock_unlock(bypassd_spinlock_t *l) {
    __atomic_store_n(&l->locked, 0, __ATOMIC_RELEASE);
}

static inline int bypassd_spinlock_is_locked(bypassd_spinlock_t *l) {
    return __atomic_load_n(&l->locked, __ATOMIC_ACQUIRE);
} 
