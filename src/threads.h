#ifndef __THREADS_H__
#define __THREADS_H__

#ifdef HAVE_MINGW
typedef HANDLE thread_t;
typedef CRITICAL_SECTION mutex_t;

static inline bool thread_create(thread_t *tid, void (*func)(void *), void *arg) {
	*tid = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, arg, 0, NULL);
	return tid;
}
static inline void thread_destroy(thread_t *tid) {
	WaitForSingleObject(tid, 0);
	CloseHandle(tid);
}
static inline void mutex_create(mutex_t *mutex) {
	InitializeCriticalSection(mutex);
}
static inline void mutex_lock(mutex_t *mutex) {
	EnterCriticalSection(mutex);
}
static inline void mutex_unlock(mutex_t *mutex) {
	LeaveCriticalSection(mutex);
}
#else
#include <pthread.h>

typedef pthread_t thread_t;
typedef pthread_mutex_t mutex_t;

static inline bool thread_create(thread_t *tid, void (*func)(void *), void *arg) {
	return !pthread_create(tid, NULL, (void *(*)(void *))func, arg);
}
static inline void thread_destroy(thread_t *tid) {
	pthread_cancel(*tid);
	pthread_join(*tid, NULL);
}
static inline void mutex_create(mutex_t *mutex) {
	pthread_mutex_init(mutex, NULL);
}
#if 1
#define mutex_lock(m) logger(LOG_DEBUG, "mutex_lock() at " __FILE__ " line %d", __LINE__); pthread_mutex_lock(m)
#define mutex_unlock(m) logger(LOG_DEBUG, "mutex_unlock() at " __FILE__ " line %d", __LINE__); pthread_mutex_unlock(m)
#else
static inline void mutex_lock(mutex_t *mutex) {
	pthread_mutex_lock(mutex);
}
static inline void mutex_unlock(mutex_t *mutex) {
	pthread_mutex_unlock(mutex);
}
#endif
#endif

#endif
