#include <emmintrin.h>
#include <stdatomic.h>

typedef struct {
    volatile int locked;
} userlib_spinlock_t;

static inline void userlib_pause() {
    _mm_pause();
}

static inline void userlib_wait_until_equal(volatile uint32_t *addr, uint32_t expected,
        int memorder) {
    while (__atomic_load_n(addr, memorder) != expected)
        userlib_pause();
}

static inline void userlib_spinlock_init(userlib_spinlock_t *l) {
    l->locked = 0;
}

static inline void userlib_spinlock_lock(userlib_spinlock_t *l) {
    int exp = 0;
    while (!__atomic_compare_exchange_n(&l->locked, &exp, 1, 0,
                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
       userlib_wait_until_equal((volatile uint32_t *)&l->locked, 0,
                __ATOMIC_RELAXED);
        exp = 0;
    }
}

static inline int userlib_spinlock_trylock(userlib_spinlock_t *l) {
    int exp = 0;
    return __atomic_compare_exchange_n(&l->locked, &exp, 1, 0,
                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static inline void userlib_spinlock_unlock(userlib_spinlock_t *l) {
    __atomic_store_n(&l->locked, 0, __ATOMIC_RELEASE);
}

static inline int userlib_spinlock_is_locked(userlib_spinlock_t *l) {
    return __atomic_load_n(&l->locked, __ATOMIC_ACQUIRE);
} 
