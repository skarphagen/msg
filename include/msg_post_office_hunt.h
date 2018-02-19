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

#ifndef MSG_POST_OFFICE_HUNT_H
#define MSG_POST_OFFICE_HUNT_H

#include <stdint.h>
#include <msg_post_office.h>
#include <msgh.h>

struct post_office_hunt_info {
        struct msgh *msgh;
        char *name;
};

typedef int (post_office_hunt_func)(const struct post_office_hunt_info *info,
                                    void *user);

struct msgh *post_office_hunt(struct msgh *msgh, const char *name,
			      uint32_t atmo);

struct msgh *post_office_hunt_cancel(uint64_t reference, uint64_t pid);

void post_office_hunt_resolve(uint64_t pid, const char *name);

void post_office_hunt_clear(uint64_t pid);

void post_office_hunt_foreach(post_office_hunt_func *func, void *user);

void post_office_hunt_snoop(uint64_t pid, uint32_t atmo);

#endif
