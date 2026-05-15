/* Shared TLS-terminated HTTP mock server for OCI test suites
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Moved here from tests/test-oci-fetch.c so both the fetch and the pull test
 * suites can drive the same listener without duplicating the OpenSSL + socket
 * scaffolding. Behaviour is unchanged; only the symbol names gained an
 * oci_mock_ prefix and a few helpers (scratch_root, base_url, wipe_dir) moved
 * along to keep their callers terse.
 */

#include "oci-mock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

ssize_t oci_mock_io_read(oci_mock_io_t *io, void *buf, size_t cap)
{
    int n = SSL_read(io->ssl, buf, (int) cap);
    return n > 0 ? (ssize_t) n : -1;
}

void oci_mock_io_write(oci_mock_io_t *io, const void *buf, size_t n)
{
    const char *p = buf;
    size_t left = n;
    while (left) {
        int w = SSL_write(io->ssl, p, (int) left);
        if (w <= 0)
            return;
        p += w;
        left -= (size_t) w;
    }
}

static ssize_t read_request_until_empty(oci_mock_io_t *io, char *buf, size_t cap)
{
    size_t off = 0;
    while (off + 1 < cap) {
        ssize_t n = oci_mock_io_read(io, buf + off, cap - 1 - off);
        if (n <= 0)
            break;
        off += (size_t) n;
        buf[off] = '\0';
        if (strstr(buf, "\r\n\r\n"))
            break;
    }
    return (ssize_t) off;
}

static void parse_request(const char *raw, oci_mock_request_t *out)
{
    memset(out, 0, sizeof(*out));
    const char *sp1 = strchr(raw, ' ');
    if (!sp1)
        return;
    size_t mlen = (size_t) (sp1 - raw);
    if (mlen >= sizeof(out->method))
        mlen = sizeof(out->method) - 1;
    memcpy(out->method, raw, mlen);
    const char *sp2 = strchr(sp1 + 1, ' ');
    if (!sp2)
        return;
    size_t plen = (size_t) (sp2 - sp1 - 1);
    if (plen >= sizeof(out->path))
        plen = sizeof(out->path) - 1;
    memcpy(out->path, sp1 + 1, plen);

    const char *line = strstr(raw, "\r\n");
    if (!line)
        return;
    line += 2;
    while (*line && strncmp(line, "\r\n", 2) != 0) {
        const char *eol = strstr(line, "\r\n");
        if (!eol)
            break;
        size_t llen = (size_t) (eol - line);
        if (llen > 13 && !strncasecmp(line, "Authorization:", 14)) {
            const char *v = line + 14;
            while (*v == ' ')
                v++;
            size_t vlen = (size_t) (eol - v);
            if (vlen >= sizeof(out->authorization))
                vlen = sizeof(out->authorization) - 1;
            memcpy(out->authorization, v, vlen);
            out->authorization[vlen] = '\0';
        } else if (llen > 6 && !strncasecmp(line, "Accept:", 7)) {
            const char *v = line + 7;
            while (*v == ' ')
                v++;
            size_t vlen = (size_t) (eol - v);
            if (vlen >= sizeof(out->accept))
                vlen = sizeof(out->accept) - 1;
            memcpy(out->accept, v, vlen);
            out->accept[vlen] = '\0';
        }
        line = eol + 2;
    }
}

static void *mock_server_loop(void *arg)
{
    oci_mock_server_t *s = arg;
    while (1) {
        pthread_mutex_lock(&s->lock);
        bool stop = s->stop;
        pthread_mutex_unlock(&s->lock);
        if (stop)
            break;
        int cfd = accept(s->listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        SSL *ssl = SSL_new(s->ssl_ctx);
        if (!ssl) {
            close(cfd);
            continue;
        }
        SSL_set_fd(ssl, cfd);
        if (SSL_accept(ssl) <= 0) {
            /* Negative-trust tests deliberately abort the handshake; just
             * recycle the socket and let the request log stay empty so the
             * caller can assert n_requests == 0.
             */
            SSL_free(ssl);
            close(cfd);
            continue;
        }
        oci_mock_io_t io = {.ssl = ssl};
        char buf[8192];
        ssize_t got = read_request_until_empty(&io, buf, sizeof(buf));
        if (got <= 0) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(cfd);
            continue;
        }
        oci_mock_request_t req;
        parse_request(buf, &req);

        pthread_mutex_lock(&s->lock);
        if (s->n_requests < OCI_MOCK_LOG_MAX) {
            s->log[s->n_requests++] = req;
        }
        oci_mock_handler_t h = s->handler;
        pthread_mutex_unlock(&s->lock);

        if (h)
            h(s, &io, &req);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
    }
    return NULL;
}

/* Generate an in-memory RSA keypair + self-signed cert valid for one day,
 * covering CN=127.0.0.1 plus SAN IP:127.0.0.1 and DNS:localhost. Writes the
 * certificate (PEM) to s->ca_pem_path for the fetcher to consume as
 * opts.ca_file.
 */
static int mock_make_cert(oci_mock_server_t *s, const char *scratch_root)
{
    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    if (!pkey)
        return -1;
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24);
    X509_set_pubkey(cert, pkey);
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *) "127.0.0.1", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    X509V3_CTX vctx;
    X509V3_set_ctx_nodb(&vctx);
    X509V3_set_ctx(&vctx, cert, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &vctx,
                                              NID_subject_alt_name,
                                              "IP:127.0.0.1, DNS:localhost");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (!X509_sign(cert, pkey, EVP_sha256())) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }

    snprintf(s->ca_pem_path, sizeof(s->ca_pem_path), "%s/mock-ca.pem",
             scratch_root);
    FILE *fp = fopen(s->ca_pem_path, "w");
    if (!fp) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }
    PEM_write_X509(fp, cert);
    fclose(fp);

    s->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!s->ssl_ctx) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }
    SSL_CTX_set_min_proto_version(s->ssl_ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate(s->ssl_ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(s->ssl_ctx, pkey) != 1) {
        SSL_CTX_free(s->ssl_ctx);
        s->ssl_ctx = NULL;
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return 0;
}

int oci_mock_server_start(oci_mock_server_t *s, const char *scratch_root)
{
    memset(s, 0, sizeof(*s));
    pthread_mutex_init(&s->lock, NULL);
    if (mock_make_cert(s, scratch_root) < 0) {
        pthread_mutex_destroy(&s->lock);
        return -1;
    }
    s->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->listen_fd < 0)
        goto err;
    int yes = 1;
    setsockopt(s->listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = 0,
    };
    if (bind(s->listen_fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
        goto err_sock;
    socklen_t slen = sizeof(sa);
    if (getsockname(s->listen_fd, (struct sockaddr *) &sa, &slen) < 0)
        goto err_sock;
    s->port = ntohs(sa.sin_port);
    if (listen(s->listen_fd, 8) < 0)
        goto err_sock;
    if (pthread_create(&s->thread, NULL, mock_server_loop, s) != 0)
        goto err_sock;
    return 0;
err_sock:
    close(s->listen_fd);
err:
    SSL_CTX_free(s->ssl_ctx);
    pthread_mutex_destroy(&s->lock);
    return -1;
}

void oci_mock_server_stop(oci_mock_server_t *s)
{
    pthread_mutex_lock(&s->lock);
    s->stop = true;
    pthread_mutex_unlock(&s->lock);
    int wake = socket(AF_INET, SOCK_STREAM, 0);
    if (wake >= 0) {
        struct sockaddr_in sa = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
            .sin_port = htons(s->port),
        };
        (void) connect(wake, (struct sockaddr *) &sa, sizeof(sa));
        close(wake);
    }
    pthread_join(s->thread, NULL);
    close(s->listen_fd);
    SSL_CTX_free(s->ssl_ctx);
    pthread_mutex_destroy(&s->lock);
}

void oci_mock_set_handler(oci_mock_server_t *s, oci_mock_handler_t h, void *ctx)
{
    pthread_mutex_lock(&s->lock);
    s->handler = h;
    s->ctx = ctx;
    s->n_requests = 0;
    memset(s->log, 0, sizeof(s->log));
    pthread_mutex_unlock(&s->lock);
}

int oci_mock_request_count(oci_mock_server_t *s)
{
    pthread_mutex_lock(&s->lock);
    int n = s->n_requests;
    pthread_mutex_unlock(&s->lock);
    return n;
}

void *oci_mock_handler_ctx(oci_mock_server_t *s)
{
    return s->ctx;
}

void oci_mock_send_full(oci_mock_io_t *io, int status, const char *status_text,
                        const char *content_type,
                        const char *www_authenticate,
                        const char *docker_digest,
                        const void *body,
                        size_t body_len)
{
    char header[1024];
    int n = snprintf(header, sizeof(header),
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Length: %zu\r\n",
                     status, status_text ? status_text : "OK", body_len);
    if (content_type)
        n += snprintf(header + n, sizeof(header) - (size_t) n,
                      "Content-Type: %s\r\n", content_type);
    if (www_authenticate)
        n += snprintf(header + n, sizeof(header) - (size_t) n,
                      "Www-Authenticate: %s\r\n", www_authenticate);
    if (docker_digest)
        n += snprintf(header + n, sizeof(header) - (size_t) n,
                      "Docker-Content-Digest: %s\r\n", docker_digest);
    n += snprintf(header + n, sizeof(header) - (size_t) n, "\r\n");
    oci_mock_io_write(io, header, (size_t) n);
    if (body_len > 0)
        oci_mock_io_write(io, body, body_len);
}

static int remove_entry(const char *path, const struct stat *st, int typeflag,
                        struct FTW *ftwbuf)
{
    (void) st;
    (void) typeflag;
    (void) ftwbuf;
    return remove(path);
}

void oci_mock_wipe_dir(const char *root)
{
    /* FTW_DEPTH walks children before parents so rmdir does not race against
     * still-populated directories.
     */
    (void) nftw(root, remove_entry, 8, FTW_DEPTH | FTW_PHYS);
}

char *oci_mock_make_scratch_root(const char *prefix)
{
    char buf[256];
    int n = snprintf(buf, sizeof(buf), "/tmp/%s-XXXXXX",
                     prefix && *prefix ? prefix : "elfuse-mock");
    if (n < 0 || (size_t) n >= sizeof(buf))
        return NULL;
    if (!mkdtemp(buf))
        return NULL;
    return strdup(buf);
}

char *oci_mock_make_base_url(int port)
{
    char *url = malloc(64);
    if (!url)
        return NULL;
    snprintf(url, 64, "https://127.0.0.1:%d", port);
    return url;
}
