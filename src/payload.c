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
#include <stdarg.h>

#include "logging.h"
#include "globvar.h"

#define BUFFLEN 2000
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

struct zerorate_http_template {
    const char *host;
    const char
        *headers; /* WITHOUT trailing CRLF, may contain internal \\r\\n */
};

static const struct zerorate_http_template zerorate_templates[] = {
    {
        .host = "vali-dns.cp31.ott.cibntv.net",
        .headers = "Range: bytes=25165824-32586598\r\n"
                   "Accept: */*",
    },
    {
        .host = "ltevod.tv189.cn",
        .headers = "Connection: Keep-Alive\r\n"
                   "Accept-Encoding: gzip",
    },
    {
        .host = "woif.10155.com",
        .headers = "Accept-Encoding: gzip",
    },
    {
        .host = "szminorshort.weixin.qq.com",
        .headers = "Upgrade: mmtls\r\n"
                   "Accept: */*\r\n"
                   "Connection: close\r\n"
                   "Content-Type: application/octet-stream",
    },
    {
        .host = "adashbc.m.taobao.com",
        .headers = "Accept-Encoding: gzip",
    },
    {
        .host = "asp.cntv.myalicdn.com",
        .headers = "Icy-MetaData: 1",
    },
    {
        .host = "dm.toutiao.com",
        .headers = "Connection: Keep-Alive\r\n"
                   "Accept-Encoding: gzip",
    },
    {
        .host = "tbcdn.hiphotos.baidu.com",
        .headers = "needginfo: 1\r\n"
                   "Connection: Keep-Alive\r\n"
                   "User-Agent: bdtb for Android 9.0.8.0",
    },
    {
        .host = "data.video.qiyi.com",
        .headers = "Accept: */*",
    },
    {
        .host = "apimeishi.meituan.com",
        .headers = "Connection: Keep-Alive",
    },
    {
        .host = "mps.amap.com",
        .headers = "Connection: Keep-Alive\r\n"
                   "Accept-Encoding: gzip",
    },
};

static int rand_range(int min, int max)
{
    if (max <= min) {
        return min;
    }
    return min + rand() % (max - min + 1);
}

static void rand_hex(char *dst, size_t hex_len)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    if (!dst || hex_len == 0) {
        return;
    }
    for (i = 0; i < hex_len; i++) {
        dst[i] = hex[rand() % (sizeof(hex) - 1)];
    }
    dst[hex_len] = '\0';
}

static void make_random_carrier_uri(char *dst, size_t dstlen)
{
    int which = rand_range(0, 2);
    char token[33];
    char access_token[33];

    rand_hex(token, 32);
    rand_hex(access_token, 32);

    if (which == 0) {
        /* /ik4g/v/C40605803.html?appid=...&token=...&devid=...&version=...&channelid=...
         */
        unsigned int c_id = (unsigned int) rand_range(10000000, 99999999);
        unsigned int appid_hi = (unsigned int) rand_range(100000, 999999);
        unsigned int appid_lo = (unsigned int) rand_range(100000, 999999);
        unsigned int devid = (unsigned int) rand_range(0, 999999);
        unsigned int channelid = (unsigned int) rand_range(10000000, 99999999);
        int v1 = rand_range(1, 9);
        int v2 = rand_range(0, 9);
        int v3 = rand_range(0, 99);
        int v4 = rand_range(0, 99);
        int ctch = rand_range(1, 9);
        snprintf(
            dst, dstlen,
            "/ik4g/v/C%08u.html?appid=%06u%06u&token=%s&devid=%06u&version="
            "%d.%d.%d.%dctch%d&channelid=%08u",
            c_id, appid_hi, appid_lo, token, devid, v1, v2, v3, v4, ctch,
            channelid);
    } else if (which == 1) {
        /* /res/V/1388/mp3/33/58/94/1388335894003000.mp3?mb=...&fs=...&... */
        unsigned int vdir = (unsigned int) rand_range(1000, 9999);
        unsigned int a = (unsigned int) rand_range(10, 99);
        unsigned int b = (unsigned int) rand_range(10, 99);
        unsigned int c = (unsigned int) rand_range(10, 99);
        unsigned int file_prefix = (unsigned int) rand_range(1000, 9999);
        unsigned int f1 = (unsigned int) rand_range(10, 99);
        unsigned int f2 = (unsigned int) rand_range(10, 99);
        unsigned int f3 = (unsigned int) rand_range(10, 99);
        unsigned int f4 = (unsigned int) rand_range(1000, 9999);
        unsigned int fs = (unsigned int) rand_range(1000000, 99999999);
        unsigned int s = (unsigned int) rand_range(100, 900);
        unsigned int id = (unsigned int) rand_range(10000000, 99999999);
        unsigned int sid = (unsigned int) rand_range(100000000, 999999999);
        /* 构造 11 位手机号样式：1 + 10位数字（用两段 5 位拼接，避免溢出） */
        unsigned int mb_a = (unsigned int) rand_range(0, 99999);
        unsigned int mb_b = (unsigned int) rand_range(0, 99999);

        snprintf(dst, dstlen,
                 "/res/V/%04u/mp3/%02u/%02u/%02u/%04u%02u%02u%02u%04u.mp3?"
                 "mb=1%05u%05u&fs=%u&s=%u&n=&id=%u&M=online&sid=%u",
                 vdir, a, b, c, file_prefix, f1, f2, f3, f4, mb_a, mb_b, fs, s,
                 id, sid);
    } else {
        /* /api/v2/egame/log.json?access_token=...&imsi=...&vc=...&... */
        unsigned int imsi_tail = (unsigned int) rand_range(100000000,
                                                           999999999);
        unsigned int vc = (unsigned int) rand_range(10, 300);
        unsigned int app_key = (unsigned int) rand_range(1000000, 9999999);
        unsigned int channel_id = (unsigned int) rand_range(10000000,
                                                            99999999);
        snprintf(dst, dstlen,
                 "/api/v2/egame/log.json?access_token=%s&imsi=4600%011u&vc=%u&"
                 "app_key=%u&channel_id=%u",
                 access_token, imsi_tail, vc, app_key, channel_id);
    }
}

static void make_random_post_uri(char *dst, size_t dstlen)
{
    /* 模拟上传/提交类接口 */
    int which = rand_range(0, 1);
    unsigned int id = (unsigned int) rand_range(10000000, 99999999);

    if (which == 0) {
        /* /api/v1/upload?file_id=...&session=... */
        snprintf(dst, dstlen, "/api/v1/upload?file_id=%08u&session=%s", id,
                 (rand_range(0, 1) == 0) ? "sess" : "auth");
    } else {
        /* /user/profile/update?uid=...&token=... */
        snprintf(dst, dstlen, "/user/profile/update?uid=%08u&token=%s", id,
                 (rand_range(0, 1) == 0) ? "auth" : "token");
    }
}

static void make_random_put_uri(char *dst, size_t dstlen)
{
    /* 模拟日志/上报接口 */
    int which = rand_range(0, 1);
    unsigned int id = (unsigned int) rand_range(10000000, 99999999);
    unsigned int r = (unsigned int) rand();

    if (which == 0) {
        /* /log/collect?device_id=...&ts=... */
        snprintf(dst, dstlen, "/log/collect?device_id=%08u&ts=%u", id, r);
    } else {
        /* /api/v2/report?event_id=...&trace_id=... */
        snprintf(dst, dstlen, "/api/v2/report?event_id=%08u&trace_id=%u", id,
                 r);
    }
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

/*
 * 生成随机小数，格式：0.xxxxxxxxxxxxxxxxx (17位小数)
 * 例如：0.6406337111524206
 */
static void generate_random_decimal(char *buf, size_t buflen)
{
    /* 生成 17 位随机数字 */
    unsigned long long r1, r2, r3;
    r1 = (unsigned long long) rand() % 1000000; /* 6位 */
    r2 = (unsigned long long) rand() % 1000000; /* 6位 */
    r3 = (unsigned long long) rand() % 100000;  /* 5位 */
    snprintf(buf, buflen, "0.%06llu%06llu%05llu", r1, r2, r3);
}

static int make_http_simple(uint8_t *buffer, size_t *len)
{
    const struct browser_profile *bp;
    char *p;
    size_t remain, buffsize;
    char uri_r[32], referer_r[32];
    int r;

    buffsize = *len;
    if (buffsize < 256) {
        E("ERROR: buffer is too small for HTTP simple payload");
        return -1;
    }

    p = (char *) buffer;
    remain = buffsize;

    /* 1. 随机选择浏览器 Profile */
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

    /* 2. 生成两个不同的随机小数（URI 和 Referer 中的 r 参数） */
    do {
        generate_random_decimal(uri_r, sizeof(uri_r));
        generate_random_decimal(referer_r, sizeof(referer_r));
    } while (strcmp(uri_r, referer_r) == 0); /* 确保不重复 */

    /* 3. 构建 HTTP 请求 */
    /* Request Line: POST /backend/empty.php?r=... HTTP/1.1 */
    if (append_format(&p, &remain, "POST /backend/empty.php?r=%s HTTP/1.1\r\n",
                      uri_r) < 0) {
        return -1;
    }

    /* Host */
    if (append_format(&p, &remain, "Host: test.ustc.edu.cn\r\n") < 0) {
        return -1;
    }

    /* User-Agent */
    if (append_format(&p, &remain, "User-Agent: %s\r\n", bp->ua) < 0) {
        return -1;
    }

    /* Referer */
    if (append_format(
            &p, &remain,
            "Referer: "
            "https://test.ustc.edu.cn/speedtest_worker.js.php?r=%s\r\n",
            referer_r) < 0) {
        return -1;
    }

    /* Header 结束空行 */
    if (append_format(&p, &remain, "\r\n") < 0) {
        return -1;
    }

    *len = buffsize - remain;

    return 0;
}

static void generate_cipher_like_body(uint8_t *buf, size_t len)
{
    static const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    size_t i;

    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t) charset[rand() % (sizeof(charset) - 1)];
    }
}

static int make_http_zerorate_from_template(
    uint8_t *buffer, size_t *len, const struct zerorate_http_template *tpl)
{
    char *p;
    size_t remain, buffsize;
    int use_post;
    const char *method_str;
    size_t body_len = 0;
    uint8_t body_buf[100];

    buffsize = *len;
    if (buffsize < 256) {
        E("ERROR: buffer is too small for HTTP zerorate payload");
        return -1;
    }

    p = (char *) buffer;
    remain = buffsize;

    /* 随机选择 GET / POST */
    use_post = rand_range(0, 1);
    method_str = use_post ? "POST" : "GET";

    /* 请求行 */
    if (append_format(&p, &remain, "%s / HTTP/1.1\r\n", method_str) < 0) {
        return -1;
    }

    /* Host */
    if (append_format(&p, &remain, "Host: %s\r\n", tpl->host) < 0) {
        return -1;
    }

    /* 固定头部 */
    if (append_format(&p, &remain, "%s\r\n", tpl->headers) < 0) {
        return -1;
    }

    if (use_post) {
        /* 生成一个 < 100 字节的“加密风格” body */
        body_len = (size_t) rand_range(32, 96);
        if (body_len > sizeof(body_buf)) {
            body_len = sizeof(body_buf);
        }
        generate_cipher_like_body(body_buf, body_len);

        /* 把 Content-Type/Content-Length 补齐到 header 里 */
        if (append_format(&p, &remain,
                          "Content-Type: application/octet-stream\r\n") < 0) {
            return -1;
        }

        if (append_format(&p, &remain, "Content-Length: %zu\r\n", body_len) <
            0) {
            return -1;
        }
    }

    /* Header 结束空行 */
    if (append_format(&p, &remain, "\r\n") < 0) {
        return -1;
    }

    /* 写入 body（仅 POST） */
    if (use_post && body_len > 0) {
        if (append_raw(&p, &remain, body_buf, body_len) < 0) {
            return -1;
        }
    }

    *len = buffsize - remain;

    return 0;
}

/* 如需按报文生成时再随机选择模板，可在以后使用该内部函数 */

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
    char pathbuf[512];
    int method; /* 0: GET, 1: POST, 2: PUT, 3: OPTIONS */
    int is_top_level;
    int is_cross_origin;
    int has_origin;
    int has_referer;
    int target_method_for_cors;
    size_t body_len = 0;
    uint8_t body_buf[100];
    int r;

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
            make_random_carrier_uri(pathbuf, sizeof(pathbuf));
            path = pathbuf;
            break;
        case 1:
            method_str = "POST";
            make_random_post_uri(pathbuf, sizeof(pathbuf));
            path = pathbuf;
            break;
        case 2:
            method_str = "PUT";
            make_random_put_uri(pathbuf, sizeof(pathbuf));
            path = pathbuf;
            break;
        case 3:
        default:
            method_str = "OPTIONS";
            make_random_carrier_uri(pathbuf, sizeof(pathbuf));
            path = pathbuf;
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

    /* 5. HEAD LINE: METHOD PATH HTTP/1.1 */
    if (append_format(&p, &remain, "%s %s HTTP/1.1\r\n", method_str, path) <
        0) {
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
        body_len = (size_t) rand_range(24, 96); /* < 100 bytes */
        if (body_len >= sizeof(body_buf)) {
            body_len = sizeof(body_buf) - 1;
        }

        /* “加密风格”内容：Base64/随机密文样式 */
        generate_cipher_like_body(body_buf, body_len);

        if (append_format(&p, &remain,
                          "Content-Type: application/octet-stream\r\n") < 0) {
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

/*
 * 将当前的 payload 环形链表打乱成随机顺序。
 * 仅在初始化阶段调用一次即可。
 */
static void shuffle_payload_ring(void)
{
    struct payload_node *node;
    struct payload_node **nodes;
    size_t count, i;

    if (!current_node) {
        return;
    }

    /* 0 或 1 个节点，无需打乱 */
    if (current_node->next == current_node) {
        return;
    }

    /* 1. 统计节点数量 */
    count = 0;
    node = current_node;
    do {
        count++;
        node = node->next;
    } while (node != current_node);

    /* 2. 拷贝到数组中 */
    nodes = malloc(count * sizeof(*nodes));
    if (!nodes) {
        E("ERROR: malloc(): %s", strerror(errno));
        return;
    }

    node = current_node;
    for (i = 0; i < count; i++) {
        nodes[i] = node;
        node = node->next;
    }

    /* 3. Fisher–Yates 洗牌 */
    for (i = count - 1; i > 0; i--) {
        size_t j = (size_t) rand_range(0, (int) i);
        struct payload_node *tmp = nodes[i];
        nodes[i] = nodes[j];
        nodes[j] = tmp;
    }

    /* 4. 根据打乱后的顺序重新链接成环 */
    for (i = 0; i + 1 < count; i++) {
        nodes[i]->next = nodes[i + 1];
    }
    nodes[count - 1]->next = nodes[0];

    /* 从新的首节点开始轮询 */
    current_node = nodes[0];

    free(nodes);
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

            case FH_PAYLOAD_TLS_CLIENT_HELLO:
                len = sizeof(node->payload);
                res = make_tls_client_hello(node->payload, &len, pinfo->info);
                if (res < 0) {
                    E(T(make_tls_client_hello));
                    goto cleanup;
                }
                node->payload_len = len;
                break;

            case FH_PAYLOAD_HTTP_RANDOM: {
                /*
                 * 对于每个 -c 传入的 hostname，预先生成多份随机 HTTP 报文，
                 * 并全部挂到环形链表中，后续循环复用。
                 *
                 * 目前实现为：每个 hostname 生成 100 份随机报文。
                 */
                size_t i;
                struct payload_node *use_node;

                for (i = 0; i < 100; i++) {
                    if (i == 0) {
                        /* 第一个报文复用当前分配的 node */
                        use_node = node;
                    } else {
                        /* 其余报文各自分配一个 node，并插入到环形链表中 */
                        use_node = malloc(sizeof(*use_node));
                        if (!use_node) {
                            E("ERROR: malloc(): %s", strerror(errno));
                            goto cleanup;
                        }

                        if (current_node) {
                            next = current_node->next;
                            current_node->next = use_node;
                            use_node->next = next;
                        } else {
                            current_node = use_node;
                            use_node->next = use_node;
                        }
                    }

                    len = sizeof(use_node->payload);
                    /*
                     *   pinfo->info 为单次 -c 传入的 hostname；
                     *   如果需要基于所有 -c 的 hostname 进行组合/随机，
                     *   可以在 make_http_random 内部遍历 g_ctx.plinfo。
                     */
                    res = make_http_random(use_node->payload, &len,
                                           pinfo->info);
                    if (res < 0) {
                        E(T(make_http_random));
                        goto cleanup;
                    }
                    use_node->payload_len = len;
                    current_node = use_node;
                }
                break;
            }

            case FH_PAYLOAD_HTTP_SIMPLE:
                len = sizeof(node->payload);
                res = make_http_simple(node->payload, &len);
                if (res < 0) {
                    E(T(make_http_simple));
                    goto cleanup;
                }
                node->payload_len = len;
                break;

            case FH_PAYLOAD_HTTP_ZERORATE: {
                size_t tcount = sizeof(zerorate_templates) /
                                sizeof(zerorate_templates[0]);
                size_t ti;
                struct payload_node *use_node;

                for (ti = 0; ti < tcount; ti++) {
                    if (ti == 0) {
                        /* 第一个模板复用当前分配的 node */
                        use_node = node;
                    } else {
                        /* 其余模板各自分配一个 node，并插入到环形链表中 */
                        use_node = malloc(sizeof(*use_node));
                        if (!use_node) {
                            E("ERROR: malloc(): %s", strerror(errno));
                            goto cleanup;
                        }

                        if (current_node) {
                            next = current_node->next;
                            current_node->next = use_node;
                            use_node->next = next;
                        } else {
                            current_node = use_node;
                            use_node->next = use_node;
                        }
                    }

                    len = sizeof(use_node->payload);
                    res = make_http_zerorate_from_template(
                        use_node->payload, &len, &zerorate_templates[ti]);
                    if (res < 0) {
                        E(T(make_http_zerorate_from_template));
                        goto cleanup;
                    }
                    use_node->payload_len = len;
                    current_node = use_node;
                }
                break;
            }

            default:
                E("ERROR: Unknown payload type");
                goto cleanup;
        }
    }

    if (!current_node) {
        E("ERROR: No payload is available");
        goto cleanup;
    }

    /* payload 全部生成完成后，将环形链表整体打乱成随机顺序 */
    shuffle_payload_ring();

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
