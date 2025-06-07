/*
 * ipv6nft.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
 *
 * Copyright (C) 2025  MikeWang000000
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include "ipv6nft.h"

#include <inttypes.h>
#include <stdlib.h>

#include "globvar.h"
#include "logging.h"
#include "process.h"

/* TODO: NOT IMPLEMENTED */
int fh_nft6_flush(int auto_create)
{
    (void) auto_create;

    return -1;
}


/* TODO: NOT IMPLEMENTED */
int fh_nft6_add(void)
{
    return -1;
}
