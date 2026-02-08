/*
 * config_parser.h - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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

#ifndef FH_CONFIG_PARSER_H
#define FH_CONFIG_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define MAX_METHODS       30
#define MAX_URIS          300
#define MAX_HEADERS       150
#define MAX_HEADER_VALUES 60

/* Header 结构：一个 header 名可以对应多个值 */
struct http_header {
    char *name;
    char *values[MAX_HEADER_VALUES];
    size_t value_count;
};

/* HTTP 配置结构 */
struct http_config {
    char *methods[MAX_METHODS];
    size_t method_count;

    char *uris[MAX_URIS];
    size_t uri_count;

    struct http_header headers[MAX_HEADERS];
    size_t header_count;

    char *body;
    size_t body_len;
};

/* 初始化配置结构 */
void fh_config_init(struct http_config *config);

/* 释放配置结构 */
void fh_config_free(struct http_config *config);

/* 解析配置文件 */
int fh_config_parse(const char *filepath, struct http_config *config);

/* 生成 HTTP payload */
int fh_config_generate_payload(struct http_config *config, uint8_t *buffer,
                               size_t *len, size_t index);

/* 计算总共可以生成多少种不同的 payload */
size_t fh_config_get_payload_count(struct http_config *config);

#endif /* FH_CONFIG_PARSER_H */
