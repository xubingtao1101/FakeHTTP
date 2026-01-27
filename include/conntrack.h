/*
 * conntrack.h - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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

#ifndef FH_CONNTRACK_H
#define FH_CONNTRACK_H

#include <stdint.h>
#include <sys/socket.h>

int fh_conntrack_setup(void);

void fh_conntrack_cleanup(void);

/*
 * 增加连接的包计数，如果达到阈值则返回 1，否则返回 0
 * 返回 -1 表示错误
 */
int fh_conntrack_increment(struct sockaddr *saddr, struct sockaddr *daddr,
                           uint16_t sport, uint16_t dport);

/*
 * 清理连接（当检测到 FIN/RST 时调用）
 */
void fh_conntrack_remove(struct sockaddr *saddr, struct sockaddr *daddr,
                         uint16_t sport, uint16_t dport);

#endif /* FH_CONNTRACK_H */
