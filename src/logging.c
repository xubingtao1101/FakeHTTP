/*
 * logging.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "logging.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "globvar.h"

int fh_logger_setup(void)
{
    if (g_ctx.logpath) {
        g_ctx.logfp = fopen(g_ctx.logpath, "a");
        if (!g_ctx.logfp) {
            g_ctx.logfp = stderr;
            E("ERROR: fopen(): %s: %s", g_ctx.logpath, strerror(errno));
            return -1;
        }
    } else {
        g_ctx.logfp = stderr;
    }

    return 0;
}


void fh_logger_cleanup(void)
{
    if (g_ctx.logfp && g_ctx.logfp != stderr) {
        fclose(g_ctx.logfp);
        g_ctx.logfp = NULL;
    }
}


void fh_logger(const char *funcname, const char *filename, unsigned long line,
               const char *fmt, ...)
{
    va_list args;
    time_t t;
    char *stime;

    t = time(NULL);
    stime = ctime(&t);
    if (stime) {
        stime[strlen(stime) - 1] = '\0';
        fprintf(g_ctx.logfp, "%s ", stime);
    }

    fprintf(g_ctx.logfp, "[%s() - %s:%lu] ", funcname, filename, line);
    va_start(args, fmt);
    vfprintf(g_ctx.logfp, fmt, args);
    va_end(args);
    fputc('\n', g_ctx.logfp);
    fflush(g_ctx.logfp);
}


void fh_logger_raw(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(g_ctx.logfp, fmt, args);
    va_end(args);
    fflush(g_ctx.logfp);
}
