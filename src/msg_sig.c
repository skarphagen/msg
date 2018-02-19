/**
 *   Copyright (C) 2021 Skarphagen Embedded
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <msg_sig.h>
#include <pthread.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define TV_SEC(msec)  (((msec) * 1000000) / 1000000000)
#define TV_NSEC(msec) (((msec) * 1000000) % 1000000000)

static sigset_t set;

static void sig_action(int sig, siginfo_t *info, void *ucontext)
{
	(void)(sig);
	(void)(ucontext);
	(void)info;
	sig_queue(SIGQUIT);
	pause();
}

int sig_timer_create(void *reference, long msec, long interval_msec, int signo,
		     timer_t *timerid)
{
	struct itimerspec spec;
	struct sigevent event;
	timer_t id;

	event.sigev_notify = SIGEV_SIGNAL;
	event.sigev_signo = signo;
	event.sigev_value.sival_ptr = reference;
	if (timer_create(CLOCK_MONOTONIC, &event, &id))
		return -errno;
	spec.it_value.tv_sec = TV_SEC(msec);
	spec.it_value.tv_nsec = TV_NSEC(msec);
	if (!spec.it_value.tv_sec && !spec.it_value.tv_nsec)
		spec.it_value.tv_nsec = 1;
	spec.it_interval.tv_sec = TV_SEC(interval_msec);
	spec.it_interval.tv_nsec = TV_NSEC(interval_msec);
	if (timer_settime(id, 0, &spec, NULL)) {
		int err = errno;
		sig_timer_delete(id);
		return -err;
	}
	*timerid = id;
	return 0;
}

void sig_timer_delete(timer_t timerid)
{
	timer_delete(timerid);
}

void sig_block(void)
{
	struct sigaction action;

	sigfillset(&set);
	sigdelset(&set, SIGSEGV);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	action.sa_sigaction = sig_action;
	action.sa_flags = SA_SIGINFO;
	sigfillset(&action.sa_mask);
	sigaction(SIGSEGV, &action, NULL);
}

int sig_wait(void **reference)
{
	siginfo_t info;
	int sig;

	sig = sigwaitinfo(&set, &info);
	if (sig == SIGMSGTMO)
		*reference = info.si_value.sival_ptr;
	else
		*reference = NULL;
	return sig;
}

void sig_queue(int sig)
{
	union sigval value;

	value.sival_ptr = NULL;
	sigqueue(getpid(), sig, value);
}
