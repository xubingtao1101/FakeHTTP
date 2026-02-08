/*
 * config_parser.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "config_parser.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logging.h"

#define MAX_LINE_LENGTH   12288
#define MAX_METHODS       30
#define MAX_URIS          300
#define MAX_HEADERS       150
#define MAX_HEADER_VALUES 60
#define MAX_BODY_SIZE     24576
#define MAX_PAYLOAD_COUNT 100000 /* 最多生成 10 万个 payload，防止 OOM */

/* 去除字符串首尾空白字符 */
static char *trim_whitespace(char *str)
{
    char *end;

    /* 去除前导空白 */
    while (isspace((unsigned char) *str))
        str++;

    if (*str == 0)
        return str;

    /* 去除尾部空白 */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char) *end))
        end--;

    end[1] = '\0';

    return str;
}

/* 检查方法是否需要 body */
static int method_needs_body(const char *method)
{
    return (strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0 ||
            strcmp(method, "PATCH") == 0);
}

/* 初始化配置结构 */
void fh_config_init(struct http_config *config)
{
    if (!config)
        return;

    memset(config, 0, sizeof(*config));
}

/* 释放配置结构 */
void fh_config_free(struct http_config *config)
{
    size_t i, j;

    if (!config)
        return;

    /* 释放 methods */
    for (i = 0; i < config->method_count; i++) {
        free(config->methods[i]);
    }

    /* 释放 uris */
    for (i = 0; i < config->uri_count; i++) {
        free(config->uris[i]);
    }

    /* 释放 headers */
    for (i = 0; i < config->header_count; i++) {
        free(config->headers[i].name);
        for (j = 0; j < config->headers[i].value_count; j++) {
            free(config->headers[i].values[j]);
        }
    }

    /* 释放 body */
    free(config->body);

    memset(config, 0, sizeof(*config));
}

/* 解析配置文件 */
int fh_config_parse(const char *filepath, struct http_config *config)
{
    FILE *fp = NULL;
    char line[MAX_LINE_LENGTH];
    char *trimmed;
    enum {
        SECTION_NONE,
        SECTION_METHODS,
        SECTION_URIS,
        SECTION_HEADERS,
        SECTION_BODY
    } current_section = SECTION_NONE;
    int line_num = 0;
    int has_host = 0;
    size_t body_len = 0;

    if (!filepath || !config) {
        E("ERROR: Invalid arguments to fh_config_parse");
        return -1;
    }

    fh_config_init(config);

    fp = fopen(filepath, "r");
    if (!fp) {
        E("ERROR: fopen(): %s: %s", filepath, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* 去除换行符 */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }
        if (len > 0 && line[len - 1] == '\r') {
            line[len - 1] = '\0';
            len--;
        }

        trimmed = trim_whitespace(line);

        /* 跳过空行和注释 */
        if (trimmed[0] == '\0' || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        /* 检查是否是节标题 */
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (!end) {
                E("ERROR: Line %d: Invalid section header", line_num);
                goto error;
            }
            *end = '\0';
            char *section_name = trim_whitespace(trimmed + 1);

            if (strcmp(section_name, "methods") == 0) {
                current_section = SECTION_METHODS;
            } else if (strcmp(section_name, "uris") == 0) {
                current_section = SECTION_URIS;
            } else if (strcmp(section_name, "headers") == 0) {
                current_section = SECTION_HEADERS;
            } else if (strcmp(section_name, "body") == 0) {
                current_section = SECTION_BODY;
            } else {
                E("ERROR: Line %d: Unknown section [%s]", line_num,
                  section_name);
                goto error;
            }
            continue;
        }

        /* 根据当前节处理内容 */
        switch (current_section) {
            case SECTION_METHODS: {
                if (config->method_count >= MAX_METHODS) {
                    E("ERROR: Line %d: Too many methods (max %d)", line_num,
                      MAX_METHODS);
                    goto error;
                }

                /* 验证方法名 */
                if (strcmp(trimmed, "GET") != 0 &&
                    strcmp(trimmed, "POST") != 0 &&
                    strcmp(trimmed, "PUT") != 0 &&
                    strcmp(trimmed, "DELETE") != 0 &&
                    strcmp(trimmed, "HEAD") != 0 &&
                    strcmp(trimmed, "OPTIONS") != 0 &&
                    strcmp(trimmed, "PATCH") != 0) {
                    E("ERROR: Line %d: Invalid HTTP method: %s", line_num,
                      trimmed);
                    goto error;
                }

                config->methods[config->method_count] = strdup(trimmed);
                if (!config->methods[config->method_count]) {
                    E("ERROR: strdup(): %s", strerror(errno));
                    goto error;
                }
                config->method_count++;
                break;
            }

            case SECTION_URIS: {
                if (config->uri_count >= MAX_URIS) {
                    E("ERROR: Line %d: Too many URIs (max %d)", line_num,
                      MAX_URIS);
                    goto error;
                }

                /* URI 必须以 / 开头 */
                if (trimmed[0] != '/') {
                    E("ERROR: Line %d: URI must start with /: %s", line_num,
                      trimmed);
                    goto error;
                }

                config->uris[config->uri_count] = strdup(trimmed);
                if (!config->uris[config->uri_count]) {
                    E("ERROR: strdup(): %s", strerror(errno));
                    goto error;
                }
                config->uri_count++;
                break;
            }

            case SECTION_HEADERS: {
                char *colon = strchr(trimmed, ':');
                if (!colon) {
                    E("ERROR: Line %d: Invalid header format (missing ':')",
                      line_num);
                    goto error;
                }

                *colon = '\0';
                char *header_name = trim_whitespace(trimmed);
                char *header_value = trim_whitespace(colon + 1);

                if (header_name[0] == '\0' || header_value[0] == '\0') {
                    E("ERROR: Line %d: Empty header name or value", line_num);
                    goto error;
                }

                /* 检查是否是 Host header */
                if (strcasecmp(header_name, "Host") == 0) {
                    has_host = 1;
                }

                /* 查找是否已存在该 header */
                size_t i;
                int found = -1;
                for (i = 0; i < config->header_count; i++) {
                    if (strcasecmp(config->headers[i].name, header_name) ==
                        0) {
                        found = i;
                        break;
                    }
                }

                if (found >= 0) {
                    /* 已存在，添加新值 */
                    if (config->headers[found].value_count >=
                        MAX_HEADER_VALUES) {
                        E("ERROR: Line %d: Too many values for header %s (max "
                          "%d)",
                          line_num, header_name, MAX_HEADER_VALUES);
                        goto error;
                    }

                    config->headers[found]
                        .values[config->headers[found].value_count] = strdup(
                        header_value);
                    if (!config->headers[found]
                             .values[config->headers[found].value_count]) {
                        E("ERROR: strdup(): %s", strerror(errno));
                        goto error;
                    }
                    config->headers[found].value_count++;
                } else {
                    /* 新 header */
                    if (config->header_count >= MAX_HEADERS) {
                        E("ERROR: Line %d: Too many headers (max %d)",
                          line_num, MAX_HEADERS);
                        goto error;
                    }

                    config->headers[config->header_count].name = strdup(
                        header_name);
                    if (!config->headers[config->header_count].name) {
                        E("ERROR: strdup(): %s", strerror(errno));
                        goto error;
                    }

                    config->headers[config->header_count].values[0] = strdup(
                        header_value);
                    if (!config->headers[config->header_count].values[0]) {
                        E("ERROR: strdup(): %s", strerror(errno));
                        goto error;
                    }

                    config->headers[config->header_count].value_count = 1;
                    config->header_count++;
                }
                break;
            }

            case SECTION_BODY: {
                /* body 可以是多行，累积所有内容 */
                size_t line_len = strlen(trimmed);
                if (body_len + line_len + 1 > MAX_BODY_SIZE) {
                    E("ERROR: Line %d: Body too large (max %d bytes)",
                      line_num, MAX_BODY_SIZE);
                    goto error;
                }

                if (!config->body) {
                    config->body = malloc(MAX_BODY_SIZE);
                    if (!config->body) {
                        E("ERROR: malloc(): %s", strerror(errno));
                        goto error;
                    }
                    config->body[0] = '\0';
                }

                /* 如果不是第一行，添加换行符 */
                if (body_len > 0) {
                    strcat(config->body, "\n");
                    body_len++;
                }

                strcat(config->body, trimmed);
                body_len += line_len;
                config->body_len = body_len;
                break;
            }

            case SECTION_NONE:
                E("ERROR: Line %d: Content outside of any section", line_num);
                goto error;
        }
    }

    if (ferror(fp)) {
        E("ERROR: fgets(): %s: %s", filepath, strerror(errno));
        goto error;
    }

    fclose(fp);

    /* 验证配置 */
    if (config->method_count == 0) {
        E("ERROR: No methods defined in config file");
        goto error;
    }

    if (config->uri_count == 0) {
        E("ERROR: No URIs defined in config file");
        goto error;
    }

    if (config->header_count == 0 || !has_host) {
        E("ERROR: At least one Host header is required");
        goto error;
    }

    E("Config loaded: %zu methods, %zu URIs, %zu headers",
      config->method_count, config->uri_count, config->header_count);

    return 0;

error:
    if (fp) {
        fclose(fp);
    }
    fh_config_free(config);
    return -1;
}

/* 生成 HTTP payload */
int fh_config_generate_payload(struct http_config *config, uint8_t *buffer,
                               size_t *len, size_t index)
{
    char *p;
    size_t remain, buffsize;
    size_t method_idx, uri_idx;
    const char *method;
    const char *uri;
    int needs_body;
    size_t i;

    if (!config || !buffer || !len) {
        E("ERROR: Invalid arguments to fh_config_generate_payload");
        return -1;
    }

    buffsize = *len;
    if (buffsize < 256) {
        E("ERROR: Buffer too small for HTTP payload");
        return -1;
    }

    p = (char *) buffer;
    remain = buffsize;

    /* 根据 index 选择 method 和 uri */
    method_idx = index % config->method_count;
    uri_idx = (index / config->method_count) % config->uri_count;

    method = config->methods[method_idx];
    uri = config->uris[uri_idx];
    needs_body = method_needs_body(method);

    /* 请求行 */
    int n = snprintf(p, remain, "%s %s HTTP/1.1\r\n", method, uri);
    if (n < 0 || (size_t) n >= remain) {
        E("ERROR: Buffer overflow when writing request line");
        return -1;
    }
    p += n;
    remain -= n;

    /* Headers */
    for (i = 0; i < config->header_count; i++) {
        /* 根据 index 轮流选择该 header 的值 */
        size_t value_idx = (index /
                            (config->method_count * config->uri_count)) %
                           config->headers[i].value_count;
        const char *value = config->headers[i].values[value_idx];

        n = snprintf(p, remain, "%s: %s\r\n", config->headers[i].name, value);
        if (n < 0 || (size_t) n >= remain) {
            E("ERROR: Buffer overflow when writing header");
            return -1;
        }
        p += n;
        remain -= n;
    }

    /* 如果需要 body，添加 Content-Length */
    if (needs_body && config->body && config->body_len > 0) {
        n = snprintf(p, remain, "Content-Length: %zu\r\n", config->body_len);
        if (n < 0 || (size_t) n >= remain) {
            E("ERROR: Buffer overflow when writing Content-Length");
            return -1;
        }
        p += n;
        remain -= n;
    }

    /* Header 结束空行 */
    n = snprintf(p, remain, "\r\n");
    if (n < 0 || (size_t) n >= remain) {
        E("ERROR: Buffer overflow when writing header end");
        return -1;
    }
    p += n;
    remain -= n;

    /* Body (仅对需要 body 的方法) */
    if (needs_body && config->body && config->body_len > 0) {
        if (config->body_len > remain) {
            E("ERROR: Buffer overflow when writing body");
            return -1;
        }
        memcpy(p, config->body, config->body_len);
        p += config->body_len;
        remain -= config->body_len;
    }

    *len = buffsize - remain;

    return 0;
}

/* 计算总共可以生成多少种不同的 payload */
size_t fh_config_get_payload_count(struct http_config *config)
{
    size_t count;
    size_t i;

    if (!config) {
        return 0;
    }

    /* 基础组合数：methods * uris */
    count = config->method_count * config->uri_count;

    /* 乘以每个 header 的值数量 */
    for (i = 0; i < config->header_count; i++) {
        count *= config->headers[i].value_count;
    }

    return count;
}
