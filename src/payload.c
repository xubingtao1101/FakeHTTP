/*
 * payload.c - FakeHTTP: https://github.com/MikeWang000000/FakeHTTP
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
#include "payload.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "logging.h"
#include "globvar.h"

#define BUFFLEN 1200
#define SET_BE16(a, u16)         \
    do {                         \
        (a)[0] = (u16) >> (8);   \
        (a)[1] = (u16) & (0xff); \
    } while (0)

struct payload_node {
    uint8_t payload[BUFFLEN];
    size_t payload_len;
    struct payload_node *next;
};

static const char *http_fmt =
    "GET / HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Accept: */*\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36\r\n"
    "\r\n";

struct tls_ext_server_name_head {
    uint8_t type[2];
    uint8_t length[2];
    uint8_t server_name_list_length[2];
    uint8_t server_name_type;
    uint8_t server_name_length[2];
};

struct tls_ext_padding_head {
    uint8_t type[2];
    uint8_t length[2];
};

static const struct tls_client_hello {
    uint8_t data_01[11];
    uint8_t random[32];
    uint8_t session_id_length;
    uint8_t session_id[32];
    uint8_t data_02[39];
    uint8_t data_sni[275];
} cli_hello_tmpl = {
    .data_01 =
        {
            0x16,             /* handshake */
            0x03, 0x03,       /* tlsv1.2 */
            0x01, 0x81,       /* length */
            0x01,             /* client hello */
            0x00, 0x01, 0x7d, /* client hello length */
            0x03, 0x03        /* tlsv1.2 */
        },
    .session_id_length = 32,
    .data_02 =
        {
            0x00, 0x02, /* cipher suites length */
            0xc0, 0x2b, /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
            0x01,       /* compression methods length */
            0x00,       /* null */
            0x01, 0x32, /* extensions length */
            0x00, 0x0a, /* ext. supported_groups */
            0x00, 0x04, /* ext. length */
            0x00, 0x02, /* list length */
            0x00, 0x17, /* secp256r1 */
            0x00, 0x0d, /* ext. signature_algorithms */
            0x00, 0x04, /* ext. length */
            0x00, 0x02, /* list length */
            0x04, 0x03, /* ecdsa_secp256r1_sha256 */
            0x00, 0x10, /* ext. alpn */
            0x00, 0x0b, /* ext. length */
            0x00, 0x09, /* alpn length */
            0x08,       /* alpn string length */
            'h',  't',  't', 'p', '/', '1', '.', '1' /* alpn string */
        },
};

static struct payload_node *current_node;

struct browser_profile {
    const char *name;
    const char *ua;
    const char *accept;
    const char *accept_language;
    const char *accept_encoding;
    int has_sec_fetch;
    int has_upgrade_insecure_requests;
};

static const struct browser_profile browser_profiles[] = {
    /* Chrome / Windows */
    {
        .name = "Chrome/Windows",
        .ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,image/apng,*/*;q=0.8,"
                  "application/signed-exchange;v=b3;q=0.7",
        .accept_language = "zh-CN,zh;q=0.9,en;q=0.8",
        .accept_encoding = "gzip, deflate, br",
        .has_sec_fetch = 1,
        .has_upgrade_insecure_requests = 1,
    },
    /* Chrome / Android */
    {
        .name = "Chrome/Android",
        .ua = "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/123.0.0.0 Mobile Safari/537.36",
        .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,image/apng,*/*;q=0.8,"
                  "application/signed-exchange;v=b3;q=0.7",
        .accept_language = "zh-CN,zh;q=0.9,en;q=0.8",
        .accept_encoding = "gzip, deflate, br",
        .has_sec_fetch = 1,
        .has_upgrade_insecure_requests = 1,
    },
    /* Firefox / Windows */
    {
        .name = "Firefox/Windows",
        .ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) "
              "Gecko/20100101 Firefox/123.0",
        .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,*/*;q=0.8",
        .accept_language = "zh-CN,zh;q=0.9,en;q=0.8",
        .accept_encoding = "gzip, deflate, br",
        .has_sec_fetch = 0,
        .has_upgrade_insecure_requests = 0,
    },
    /* Safari / macOS */
    {
        .name = "Safari/macOS",
        .ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) "
              "Version/17.0 Safari/605.1.15",
        .accept = "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,image/apng,*/*;q=0.8",
        .accept_language = "zh-CN,zh;q=0.9,en;q=0.8",
        .accept_encoding = "gzip, deflate, br",
        .has_sec_fetch = 0,
        .has_upgrade_insecure_requests = 1,
    },
};

static int rand_range(int min, int max)
{
    if (max <= min) {
        return min;
    }
    return min + rand() % (max - min + 1);
}

static void make_speedtest_host(char *host, size_t hostlen)
{
    int a, b, c, d, port, n;

    a = rand_range(1, 100);
    b = rand_range(1, 100);
    c = rand_range(1, 100);
    d = rand_range(1, 100);

    /* 80 / 443 / 8080 之间随机 */
    n = rand_range(0, 2);
    if (n == 0) {
        port = 80;
    } else if (n == 1) {
        port = 443;
    } else {
        port = 8080;
    }

    snprintf(host, hostlen, "node-%d-%d-%d-%d.speedtest.cn:%d", a, b, c, d,
             port);
}

static void copy_host(char *dst, size_t dstlen, const char *hostname)
{
    if (hostname && hostname[0]) {
        snprintf(dst, dstlen, "%s", hostname);
    } else {
        make_speedtest_host(dst, dstlen);
    }
}

static void host_without_port(char *dst, size_t dstlen, const char *host)
{
    size_t i;

    for (i = 0; i < dstlen - 1 && host[i]; i++) {
        if (host[i] == ':') {
            break;
        }
        dst[i] = host[i];
    }
    dst[i] = '\0';
}

static int append_format(char **p, size_t *remain, const char *fmt, ...)
{
    int n;
    va_list ap;

    va_start(ap, fmt);
    n = vsnprintf(*p, *remain, fmt, ap);
    va_end(ap);

    if (n < 0) {
        return -1;
    }
    if ((size_t) n >= *remain) {
        return -1;
    }

    *p += n;
    *remain -= n;

    return 0;
}

static int append_raw(char **p, size_t *remain, const uint8_t *data,
                      size_t len)
{
    if (len > *remain) {
        return -1;
    }

    memcpy(*p, data, len);
    *p += len;
    *remain -= len;

    return 0;
}

static int make_http_random(uint8_t *buffer, size_t *len, char *hostname)
{
    const struct browser_profile *bp;
    char *p;
    size_t remain, buffsize;
    char host[128];
    char origin_host[128];
    char origin_url[256];
    char referer_url[256];
    const char *method_str;
    const char *path;
    int method; /* 0: GET, 1: POST, 2: PUT, 3: OPTIONS */
    int is_top_level;
    int is_cross_origin;
    int has_origin;
    int has_referer;
    int target_method_for_cors;
    size_t body_len = 0;
    uint8_t body_buf[256];
    int i, r;

    buffsize = *len;
    if (buffsize < 128) {
        E("ERROR: buffer is too small for HTTP random payload");
        return -1;
    }

    p = (char *) buffer;
    remain = buffsize;

    /* 1. 选择浏览器 Profile，简单加权：Chrome 占比更高 */
    r = rand_range(0, 99);
    if (r < 40) {
        bp = &browser_profiles[0]; /* Chrome / Windows */
    } else if (r < 70) {
        bp = &browser_profiles[1]; /* Chrome / Android */
    } else if (r < 85) {
        bp = &browser_profiles[2]; /* Firefox / Windows */
    } else {
        bp = &browser_profiles[3]; /* Safari / macOS */
    }

    /* 2. 产生 Host（优先使用外部列表） */
    copy_host(host, sizeof(host), hostname);
    host_without_port(origin_host, sizeof(origin_host), host);

    /* 3. 随机选择方法，稍微偏向 GET/POST */
    r = rand_range(0, 99);
    if (r < 60) {
        method = 0; /* GET */
    } else if (r < 85) {
        method = 1; /* POST */
    } else if (r < 95) {
        method = 3; /* OPTIONS */
    } else {
        method = 2; /* PUT */
    }

    switch (method) {
        case 0:
            method_str = "GET";
            path = "/download";
            break;
        case 1:
            method_str = "POST";
            path = "/upload";
            break;
        case 2:
            method_str = "PUT";
            path = "/upload";
            break;
        case 3:
        default:
            method_str = "OPTIONS";
            path = "/download";
            break;
    }

    /* 4. 是否顶级导航 / 跨域 */
    is_top_level = (method == 0 && rand_range(0, 99) < 70) ? 1 : 0;
    is_cross_origin = (rand_range(0, 99) < 30) ? 1 : 0;

    has_origin = ((method == 1) || (method == 2) || is_cross_origin) ? 1 : 0;
    has_referer = is_top_level ? 1 : 0;

    /* 为跨域构造一个简单的 Origin/Referer 来源 */
    if (is_cross_origin) {
        snprintf(origin_url, sizeof(origin_url), "https://www.example.com");
        snprintf(referer_url, sizeof(referer_url),
                 "https://www.example.com/index.html");
    } else {
        snprintf(origin_url, sizeof(origin_url), "https://%s", origin_host);
        snprintf(referer_url, sizeof(referer_url), "https://%s/index.html",
                 origin_host);
    }

    /* 5. HEAD LINE: METHOD PATH?query HTTP/1.1 */
    r = rand_range(10000, 99999);
    if (append_format(&p, &remain, "%s %s?id=%d HTTP/1.1\r\n", method_str,
                      path, r) < 0) {
        return -1;
    }

    /* 6. Header 顺序 */
    /* Host */
    if (append_format(&p, &remain, "Host: %s\r\n", host) < 0) {
        return -1;
    }

    /* Connection */
    if (append_format(&p, &remain, "Connection: keep-alive\r\n") < 0) {
        return -1;
    }

    /* Upgrade-Insecure-Requests */
    if (bp->has_upgrade_insecure_requests && method == 0) {
        if (append_format(&p, &remain, "Upgrade-Insecure-Requests: 1\r\n") <
            0) {
            return -1;
        }
    }

    /* User-Agent */
    if (append_format(&p, &remain, "User-Agent: %s\r\n", bp->ua) < 0) {
        return -1;
    }

    /* Accept */
    if (append_format(&p, &remain, "Accept: %s\r\n", bp->accept) < 0) {
        return -1;
    }

    /* Accept-Encoding */
    if (append_format(&p, &remain, "Accept-Encoding: %s\r\n",
                      bp->accept_encoding) < 0) {
        return -1;
    }

    /* Accept-Language */
    if (append_format(&p, &remain, "Accept-Language: %s\r\n",
                      bp->accept_language) < 0) {
        return -1;
    }

    /* Referer / Origin （Referer 优先） */
    if (has_referer) {
        if (append_format(&p, &remain, "Referer: %s\r\n", referer_url) < 0) {
            return -1;
        }
    }

    if (has_origin) {
        if (append_format(&p, &remain, "Origin: %s\r\n", origin_url) < 0) {
            return -1;
        }
    }

    /* 7. Content-Type / Content-Length / CORS / sec-fetch-* */
    if (method == 1 || method == 2) {
        /* POST / PUT: 必须有 body 和 Content-Length */
        body_len = (size_t) rand_range(32, 192);
        if (body_len > sizeof(body_buf)) {
            body_len = sizeof(body_buf);
        }

        /* 简单 form body：k=v&... */
        for (i = 0; i < (int) body_len; i++) {
            int ctype = rand_range(0, 2);
            if (ctype == 0) {
                body_buf[i] = (uint8_t) ('a' + rand_range(0, 25));
            } else if (ctype == 1) {
                body_buf[i] = (uint8_t) ('0' + rand_range(0, 9));
            } else {
                body_buf[i] = (uint8_t) ("=&"[rand_range(0, 1)]);
            }
        }

        if (append_format(
                &p, &remain,
                "Content-Type: application/x-www-form-urlencoded\r\n") < 0) {
            return -1;
        }

        if (append_format(&p, &remain, "Content-Length: %zu\r\n", body_len) <
            0) {
            return -1;
        }
    }

    if (method == 3) {
        /* OPTIONS: CORS 预检 */
        target_method_for_cors = (rand_range(0, 1) == 0) ? 0
                                                         : 1; /* GET/POST */
        if (append_format(&p, &remain, "Access-Control-Request-Method: %s\r\n",
                          target_method_for_cors == 0 ? "GET" : "POST") < 0) {
            return -1;
        }

        if (append_format(&p, &remain,
                          "Access-Control-Request-Headers: content-type\r\n") <
            0) {
            return -1;
        }
    }

    if (bp->has_sec_fetch) {
        const char *site = is_cross_origin ? "cross-site" : "same-origin";
        const char *mode = is_top_level ? "navigate" : "cors";
        const char *dest = is_top_level ? "document" : "empty";

        if (append_format(&p, &remain, "Sec-Fetch-Site: %s\r\n", site) < 0) {
            return -1;
        }

        if (append_format(&p, &remain, "Sec-Fetch-Mode: %s\r\n", mode) < 0) {
            return -1;
        }

        if (append_format(&p, &remain, "Sec-Fetch-Dest: %s\r\n", dest) < 0) {
            return -1;
        }

        if (is_top_level && method == 0) {
            if (append_format(&p, &remain, "Sec-Fetch-User: ?1\r\n") < 0) {
                return -1;
            }
        }
    }

    /* Header 结束空行 */
    if (append_format(&p, &remain, "\r\n") < 0) {
        return -1;
    }

    /* 写入 body（仅 POST / PUT） */
    if ((method == 1 || method == 2) && body_len > 0) {
        if (append_raw(&p, &remain, body_buf, body_len) < 0) {
            return -1;
        }
    }

    *len = buffsize - remain;

    return 0;
}

static int make_http_get(uint8_t *buffer, size_t *len, char *hostname)
{
    int len_, buffsize;

    buffsize = *len;
    len_ = snprintf((char *) buffer, buffsize, http_fmt, hostname);

    if (len_ < 0) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    } else if (len_ >= buffsize) {
        E("ERROR: hostname is too long");
        return -1;
    }

    *len = len_;

    return 0;
}


static int make_tls_client_hello(uint8_t *buffer, size_t *len, char *hostname)
{
    int padding_len;
    size_t i, buffsize;
    struct tls_client_hello *tls_data;
    struct tls_ext_server_name_head *server_name_head;
    struct tls_ext_padding_head *padding_head;

    buffsize = *len;

    if (buffsize < (int) sizeof(*tls_data)) {
        E("ERROR: buffer is too small");
        return -1;
    }

    tls_data = (struct tls_client_hello *) buffer;
    memcpy(tls_data, &cli_hello_tmpl, sizeof(cli_hello_tmpl));

    for (i = 0; i < sizeof(tls_data->random); i++) {
        tls_data->random[i] = rand();
    }

    for (i = 0; i < sizeof(tls_data->session_id); i++) {
        tls_data->session_id[i] = rand();
    }

    size_t hostname_len = strlen(hostname);

    padding_len = sizeof(tls_data->data_sni) -
                  sizeof(struct tls_ext_server_name_head) - strlen(hostname) -
                  sizeof(struct tls_ext_padding_head);

    if (padding_len < 0) {
        E("ERROR: hostname is too long");
        return -1;
    }

    server_name_head = (struct tls_ext_server_name_head *) tls_data->data_sni;
    SET_BE16(server_name_head->type, 0);
    SET_BE16(server_name_head->length, hostname_len + 5);
    SET_BE16(server_name_head->server_name_list_length, hostname_len + 3);
    SET_BE16(server_name_head->server_name_length, hostname_len);
    memcpy((uint8_t *) server_name_head + sizeof(*server_name_head), hostname,
           hostname_len);

    padding_head = (struct tls_ext_padding_head *) (tls_data->data_sni +
                                                    sizeof(*server_name_head) +
                                                    hostname_len);
    SET_BE16(padding_head->type, 21);
    SET_BE16(padding_head->length, padding_len);
    memset((uint8_t *) padding_head + sizeof(*padding_head), 0, padding_len);

    *len = sizeof(*tls_data);

    return 0;
}


static int make_custom(uint8_t *buffer, size_t *len, char *filepath)
{
    int res, len_, buffsize;
    FILE *fp;

    len_ = 0;
    buffsize = *len;

    fp = fopen(filepath, "rb");
    if (!fp) {
        E("ERROR: fopen(): %s: %s", filepath, strerror(errno));
        return -1;
    }

    while (!feof(fp) && !ferror(fp) && len_ < buffsize) {
        len_ += fread(buffer + len_, 1, buffsize - len_, fp);
    }

    if (ferror(fp)) {
        E("ERROR: fread(): %s: %s", filepath, "failure");
        fclose(fp);
        return -1;
    }

    if (!feof(fp)) {
        E("ERROR: %s: Data too long. Maximum length is %d", filepath,
          buffsize);
        fclose(fp);
        return -1;
    }

    res = fclose(fp);
    if (res < 0) {
        E("ERROR: fclose(): %s", strerror(errno));
        return -1;
    }

    *len = len_;

    return 0;
}


int fh_payload_setup(void)
{
    int res;
    size_t len;
    struct payload_info *pinfo;
    struct payload_node *node, *next;

    for (pinfo = g_ctx.plinfo; pinfo->type; pinfo++) {
        node = malloc(sizeof(*node));
        if (!node) {
            E("ERROR: malloc(): %s", strerror(errno));
            goto cleanup;
        }

        if (current_node) {
            next = current_node->next;
            current_node->next = node;
            node->next = next;
        } else {
            current_node = node;
            node->next = node;
        }

        switch (pinfo->type) {
            case FH_PAYLOAD_CUSTOM:
                len = sizeof(node->payload);
                res = make_custom(node->payload, &len, pinfo->info);
                if (res < 0) {
                    E(T(make_custom));
                    goto cleanup;
                }
                node->payload_len = len;
                break;

            case FH_PAYLOAD_HTTP:
                len = sizeof(node->payload);
                res = make_http_get(node->payload, &len, pinfo->info);
                if (res < 0) {
                    E(T(make_http_get));
                    goto cleanup;
                }
                node->payload_len = len;
                break;

            case FH_PAYLOAD_HTTPS:
                len = sizeof(node->payload);
                res = make_tls_client_hello(node->payload, &len, pinfo->info);
                if (res < 0) {
                    E(T(make_tls_client_hello));
                    goto cleanup;
                }
                node->payload_len = len;
                break;

            case FH_PAYLOAD_HTTP_RANDOM:
                len = sizeof(node->payload);
                /*
                 * NOTE:
                 *   这里调用的 make_http_random
                 * 目前只保留框架，不做实际随机报文
                 *   生成，由后续实现补充具体算法。
                 *
                 *   pinfo->info 为单次 -c 传入的 hostname；
                 *   如果需要基于所有 -c 的 hostname 进行组合/随机，
                 *   可以在 make_http_random 内部遍历 g_ctx.plinfo。
                 */
                res = make_http_random(node->payload, &len, pinfo->info);
                if (res < 0) {
                    E(T(make_http_random));
                    goto cleanup;
                }
                node->payload_len = len;
                break;

            default:
                E("ERROR: Unknown payload type");
                goto cleanup;
        }
    }

    if (!current_node) {
        E("ERROR: No payload is available");
        goto cleanup;
    }

    current_node = current_node->next;

    return 0;

cleanup:
    fh_payload_cleanup();

    return -1;
}


void fh_payload_cleanup(void)
{
    struct payload_node *node, *next_node;

    node = current_node;
    while (node) {
        next_node = node->next;
        free(node);
        if (next_node == current_node) {
            break;
        }
        node = next_node;
    }
}


void th_payload_get(uint8_t **payload_ptr, size_t *payload_len)
{
    *payload_ptr = current_node->payload;
    *payload_len = current_node->payload_len;
    current_node = current_node->next;
}
