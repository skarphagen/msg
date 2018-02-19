/**
 *   Copyright (C) 2019 Skarphagen Embedded
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

#include <msg_error.h>
#include <msg_sig.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

void error_exit(const char *fmt, ...)
{
        va_list args;

        va_start(args, fmt);
        vsyslog(LOG_INFO, fmt, args);
        va_end(args);
        sig_queue(SIGQUIT);
        while (pause() || 1);
}

void error_err(const char *fmt, ...)
{
        va_list args;

        va_start(args, fmt);
        vsyslog(LOG_ERR, fmt, args);
        va_end(args);
        sig_queue(SIGQUIT);
        while (pause() || 1);
}

void error_sig(const char *fmt, ...)
{
        va_list args;

        va_start(args, fmt);
        vsyslog(LOG_ERR, fmt, args);
        va_end(args);
        sig_queue(SIGQUIT);
}
