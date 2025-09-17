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

/*
    Generate a new payload on each call.
    - buffer: output buffer to write payload bytes
    - len: in/out. On input, size of buffer; on output, number of bytes written
    Return 0 on success, <0 on failure.
*/
static int fh_generate_new_payload(uint8_t *buffer, size_t *len)
{
    size_t left, used, wrote;
    int include_origin, include_referer;
    unsigned int a, b, c, d, port;
    unsigned int r_high, r_low;
    char hostline[160];
    char originline[200];
    char refererline[240];
    const char *methods[] = {"GET", "POST", "OPTIONS", "PUT"};
    const char *method = methods[rand() % 4];
    char ualine[256];
    static size_t host_rr_index;

    left = *len;
    used = 0;

    /* Random parts */
    a = 20 + (rand() % 80);          /* 20..99 */
    b = 1 + (rand() % 254);          /* 1..254 */
    c = 1 + (rand() % 254);          /* 1..254 */
    d = 1 + (rand() % 254);          /* 1..254 */
    port = 10000 + (rand() % 50000); /* 10000..59999 */

    /* r parameter: 0.xxxxxxxxxxxxxxxx with 16 random digits */
    r_high = (unsigned int) rand();
    r_low = (unsigned int) rand();

    include_origin = rand() & 1;
    include_referer = rand() & 1;

    /* Build Host, Origin, Referer lines into temp buffers */
    /* Prefer -h provided hostnames (type FH_PAYLOAD_HTTP); fallback to random */
    {
        size_t i, count = 0, pick = 0;
        /* First pass: count HTTP hosts */
        for (i = 0; g_ctx.plinfo && g_ctx.plinfo[i].type; i++) {
            if (g_ctx.plinfo[i].type == FH_PAYLOAD_HTTP && g_ctx.plinfo[i].info) {
                count++;
            }
        }

        if (count > 0) {
            /* Second pass: select (host_rr_index % count)-th HTTP host */
            size_t target = host_rr_index % count;
            for (i = 0; g_ctx.plinfo[i].type; i++) {
                if (g_ctx.plinfo[i].type == FH_PAYLOAD_HTTP && g_ctx.plinfo[i].info) {
                    if (pick == target) {
                        snprintf(hostline, sizeof(hostline),
                                 "Host: %s\r\n", g_ctx.plinfo[i].info);
                        break;
                    }
                    pick++;
                }
            }
            host_rr_index++;
        } else {
            snprintf(hostline, sizeof(hostline),
                     "Host: node-%u-%u-%u-%u.speedtest.cn:%u\r\n", a, b, c, d, port);
        }
    }

    if (include_origin) {
        /* Randomly choose http/https and a path */
        const char *scheme = (rand() & 1) ? "https" : "http";
        unsigned int pathpick = rand() % 3; /* 0:/, 1:/speed, 2:/test */
        const char *paths[3] = {"/", "/speed", "/test/"};
        snprintf(originline, sizeof(originline),
                 "origin: %s://www.speedtest.cn\r\n", scheme);
        snprintf(refererline, sizeof(refererline),
                 "referer: %s://www.speedtest.cn%s\r\n", scheme,
                 paths[pathpick]);
    } else {
        originline[0] = '\0';
        snprintf(refererline, sizeof(refererline),
                 "referer: https://www.speedtest.cn/\r\n");
    }

    if (!include_referer) {
        refererline[0] = '\0';
    }

    /* Start composing into buffer */
    wrote = snprintf((char *) buffer + used, left,
                     "%s /upload?r=0.%08u%08u HTTP/1.1\r\n",
                     method, r_high, r_low);
    if (wrote >= left) {
        return -1;
    }
    used += wrote;
    left -= wrote;

    wrote = snprintf((char *) buffer + used, left, "%s", hostline);
    if (wrote >= left) {
        return -1;
    }
    used += wrote;
    left -= wrote;

    /* Always include these headers */
    wrote = snprintf((char *) buffer + used, left,
                     "accept: */*\r\n");
    if (wrote >= left) {
        return -1;
    }
    used += wrote;
    left -= wrote;

    /* Slightly randomize accept-language weight */
    {
        int q = 8 + (rand() % 3); /* 0.8..1.0 step 0.1 approx */
        wrote = snprintf((char *) buffer + used, left,
                         "accept-language: zh-CN,zh;q=0.%d,en;q=0.8\r\n", q);
        if (wrote >= left) {
            return -1;
        }
        used += wrote;
        left -= wrote;
    }

    wrote = snprintf((char *) buffer + used, left,
                     "access-control-request-headers: content-type\r\n");
    if (wrote >= left) {
        return -1;
    }
    used += wrote;
    left -= wrote;

    wrote = snprintf((char *) buffer + used, left,
                     "access-control-request-method: POST\r\n");
    if (wrote >= left) {
        return -1;
    }
    used += wrote;
    left -= wrote;

    wrote = snprintf((char *) buffer + used, left,
                     "cache-control: no-cache\r\n");
    if (wrote >= left) {
        return -1;
    }
    used += wrote;
    left -= wrote;

    /* Optionally include origin and referer */
    if (originline[0]) {
        wrote = snprintf((char *) buffer + used, left, "%s", originline);
        if (wrote >= left) {
            return -1;
        }
        used += wrote;
        left -= wrote;
    }
    if (refererline[0]) {
        wrote = snprintf((char *) buffer + used, left, "%s", refererline);
        if (wrote >= left) {
            return -1;
        }
        used += wrote;
        left -= wrote;
    }

    /* Generate randomized User-Agent */
    {
        enum { UA_WIN, UA_MAC, UA_LINUX } platform = (rand() % 3);
        enum { ENG_WEBKIT, ENG_GECKO, ENG_TRIDENT } engine = (rand() % 3);
        int chrome_major = 120 + (rand() % 25);   /* 120..144 */
        int edge_major = 120 + (rand() % 25);     /* 120..144 */
        int firefox_major = 115 + (rand() % 25);  /* 115..139 */

        const char *plat_str;
        switch (platform) {
            case UA_WIN:
                plat_str = "Windows NT 10.0; Win64; x64";
                break;
            case UA_MAC:
                plat_str = "Macintosh; Intel Mac OS X 10_15_7";
                break;
            default:
                plat_str = "X11; Linux x86_64";
                break;
        }

        ualine[0] = '\0';

        if (engine == ENG_WEBKIT) {
            /* Chrome/Edge family on WebKit */
            int use_edge = rand() & 1;
            if (use_edge) {
                snprintf(ualine, sizeof(ualine),
                         "user-agent: Mozilla/5.0 (%s) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/%d.0.0.0 Safari/537.36 Edg/%d.0.0.0\r\n",
                         plat_str, chrome_major, edge_major);
            } else {
                snprintf(ualine, sizeof(ualine),
                         "user-agent: Mozilla/5.0 (%s) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/%d.0.0.0 Safari/537.36\r\n",
                         plat_str, chrome_major);
            }
        } else if (engine == ENG_GECKO) {
            /* Firefox family on Gecko */
            snprintf(ualine, sizeof(ualine),
                     "user-agent: Mozilla/5.0 (%s; rv:%d.0) "
                     "Gecko/20100101 Firefox/%d.0\r\n",
                     plat_str, firefox_major, firefox_major);
        } else {
            /* Trident (IE 11 style) */
            /* Force Windows platform for realistic UA */
            plat_str = "Windows NT 10.0; Trident/7.0; rv:11.0";
            snprintf(ualine, sizeof(ualine),
                     "user-agent: Mozilla/5.0 (%s) like Gecko\r\n",
                     plat_str);
        }

        wrote = snprintf((char *) buffer + used, left, "%s", ualine);
        if (wrote >= left) {
            return -1;
        }
        used += wrote;
        left -= wrote;
    }
    if (wrote >= left) {
        return -1;
    }
    used += wrote;
    left -= wrote;

    /* End of headers */
    wrote = snprintf((char *) buffer + used, left, "\r\n");
    if (wrote >= left) {
        return -1;
    }
    used += wrote;
    left -= wrote;

    *len = used;
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
    static uint8_t buffer[BUFFLEN];
    size_t len = sizeof(buffer);
    int res = fh_generate_new_payload(buffer, &len);

    if (res < 0) {
        *payload_ptr = NULL;
        *payload_len = 0;
        return;
    }

    *payload_ptr = buffer;
    *payload_len = len;
}
