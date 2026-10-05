/*
    resolver.c -- async host name resolution
    Copyright (C) 2026 euxane

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

/*
    Name resolution using short-lived background threads,
    to avoid blocking the main event loop.
*/

#include "system.h"

#ifndef HAVE_WINDOWS
#include <pthread.h>
#endif

#include "event.h"
#include "logger.h"
#include "net.h"
#include "resolver.h"
#include "xalloc.h"

struct resolve_t {
	// Read-only once the worker thread is started.
	char *host;
	char *service;
	struct addrinfo hint;

	// Only accessed from the event loop thread.
	resolve_cb_t cb;
	void *data;

	// Written by the worker thread before queueing the request.
	struct addrinfo *ai;
	int error;
	int sys_errno;

	// Link in the queue of completed requests, protected by the queue lock.
	resolve_t *next;
};

static struct {
	resolve_t *head;
	resolve_t *tail;
} done;

static io_t done_io;

#ifdef HAVE_WINDOWS

static SRWLOCK done_lock = SRWLOCK_INIT;

static void lock_done(void) {
	AcquireSRWLockExclusive(&done_lock);
}

static void unlock_done(void) {
	ReleaseSRWLockExclusive(&done_lock);
}

static void wake_event_loop(void) {
	WSASetEvent(done_io.event);
}

static void clear_wakeup(void) {
	WSAResetEvent(done_io.event);
}

#else

static pthread_mutex_t done_lock = PTHREAD_MUTEX_INITIALIZER;
static int wakeup_fd[2] = {-1, -1};

static void lock_done(void) {
	pthread_mutex_lock(&done_lock);
}

static void unlock_done(void) {
	pthread_mutex_unlock(&done_lock);
}

static void wake_event_loop(void) {
	const char byte = 0;

	// A full pipe already guarantees a wakeup.
	if(write(wakeup_fd[1], &byte, 1) != 1) {
		return;
	}
}

static void clear_wakeup(void) {
	char buf[64];

	while(read(wakeup_fd[0], buf, sizeof(buf)) > 0) {
		continue;
	}
}

#endif

static void free_request(resolve_t *request) {
	if(request->ai) {
		freeaddrinfo(request->ai);
	}

	free(request->host);
	free(request->service);
	free(request);
}

static void deliver(resolve_t *request) {
	if(!request->cb) {
		free_request(request);
		return;
	}

	if(request->error) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Error looking up %s port %s: %s", request->host, request->service,
		       request->error == EAI_SYSTEM ? strerror(request->sys_errno) : gai_strerror(request->error));
	}

	struct addrinfo *ai = request->ai;

	request->ai = NULL;
	request->cb(request->data, ai);
	free_request(request);
}

static void handle_done(void *data, int flags) {
	(void)data;
	(void)flags;

	// Clearing the wakeup before taking the queue ensures that no completion is missed.
	clear_wakeup();

	lock_done();
	resolve_t *request = done.head;
	done.head = done.tail = NULL;
	unlock_done();

	while(request) {
		resolve_t *next = request->next;
		deliver(request);
		request = next;
	}
}

static void resolve(resolve_t *request) {
	request->error = getaddrinfo(request->host, request->service, &request->hint, &request->ai);
	request->sys_errno = errno;

	if(request->error) {
		request->ai = NULL;
	}

	lock_done();

	if(done.tail) {
		done.tail->next = request;
	} else {
		done.head = request;
	}

	done.tail = request;
	unlock_done();

	// The request now belongs to the event loop thread.
	wake_event_loop();
}

#ifdef HAVE_WINDOWS

static bool init_done_io(void) {
	WSAEVENT event = WSACreateEvent();

	if(event == WSA_INVALID_EVENT) {
		return false;
	}

	io_add_event(&done_io, handle_done, NULL, event);
	return true;
}

static DWORD WINAPI resolve_thread(LPVOID arg) {
	resolve(arg);
	return 0;
}

static bool start_thread(resolve_t *request) {
	HANDLE thread = CreateThread(NULL, 0, resolve_thread, request, 0, NULL);

	if(!thread) {
		return false;
	}

	CloseHandle(thread);
	return true;
}

#else

static bool init_done_io(void) {
	if(pipe(wakeup_fd)) {
		return false;
	}

	for(int i = 0; i < 2; i++) {
		fcntl(wakeup_fd[i], F_SETFL, fcntl(wakeup_fd[i], F_GETFL) | O_NONBLOCK);
		fcntl(wakeup_fd[i], F_SETFD, FD_CLOEXEC);
	}

	io_add(&done_io, handle_done, NULL, wakeup_fd[0], IO_READ);
	return true;
}

static void *resolve_thread(void *arg) {
	resolve(arg);
	return NULL;
}

static bool start_thread(resolve_t *request) {
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	// Leave signal handling to the event loop thread.
	sigset_t all, old;
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &old);

	pthread_t thread;
	int err = pthread_create(&thread, &attr, resolve_thread, request);

	pthread_sigmask(SIG_SETMASK, &old, NULL);
	pthread_attr_destroy(&attr);

	if(err) {
		errno = err;
		return false;
	}

	return true;
}

#endif

resolve_t *resolve_start(const char *host, const char *service, int socktype, resolve_cb_t cb, void *data) {
	if(!done_io.cb && !init_done_io()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not set up asynchronous name resolution: %s", strerror(errno));
		return NULL;
	}

	resolve_t *request = xzalloc(sizeof(*request));
	request->host = xstrdup(host);
	request->service = xstrdup(service);
	request->hint.ai_family = addressfamily;
	request->hint.ai_socktype = socktype;
	request->cb = cb;
	request->data = data;

	if(!start_thread(request)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not start resolver thread for %s: %s", host, strerror(errno));
		free_request(request);
		return NULL;
	}

	return request;
}

void resolve_cancel(resolve_t *request) {
	request->cb = NULL;
}

struct addrinfo *resolve_numeric(const char *host, const char *service, int socktype) {
	struct addrinfo *ai, hint = {
		.ai_family = addressfamily,
		.ai_socktype = socktype,
		.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV,
	};

	return getaddrinfo(host, service, &hint, &ai) ? NULL : ai;
}
