/*
 * Copyright 2026 Various Authors
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "net.h"
#ifdef HAVE_CONFIG
#include "config/openssl.h"
#endif

#ifndef HAVE_OPENSSL
#define HAVE_OPENSSL 0
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#if HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#ifndef X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
#define X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0
#endif
#endif

struct tls_entry {
	int fd;
#if HAVE_OPENSSL
	SSL *ssl;
	SSL_CTX *ctx;
#endif
	struct tls_entry *next;
};

static struct tls_entry *tls_head;

static struct tls_entry *tls_find(int fd)
{
	struct tls_entry *cur = tls_head;

	while (cur) {
		if (cur->fd == fd)
			return cur;
		cur = cur->next;
	}
	return NULL;
}

#if HAVE_OPENSSL
static void tls_remove(struct tls_entry *entry)
{
	struct tls_entry **cur = &tls_head;

	while (*cur) {
		if (*cur == entry) {
			*cur = entry->next;
			return;
		}
		cur = &(*cur)->next;
	}
}

static int tls_wait_fd(int fd, int want_write, struct timeval *tv)
{
	fd_set rfds;
	fd_set wfds;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	if (want_write)
		FD_SET(fd, &wfds);
	else
		FD_SET(fd, &rfds);

	while (1) {
		int rc = select(fd + 1, want_write ? NULL : &rfds,
				want_write ? &wfds : NULL, NULL, tv);
		if (rc == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (rc == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		return 0;
	}
}

static void tls_init_library(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	OPENSSL_init_ssl(0, NULL);
#else
	SSL_library_init();
	SSL_load_error_strings();
#endif
}
#endif

int net_tls_connect(int fd, const char *hostname, int timeout_ms)
{
#if HAVE_OPENSSL
	struct tls_entry *entry;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	struct timeval tv;
	int flags, rc;

	tls_init_library();

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ctx = SSL_CTX_new(TLS_client_method());
#else
	ctx = SSL_CTX_new(SSLv23_client_method());
#endif
	if (ctx == NULL)
		goto err;

	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
		goto err;

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	ssl = SSL_new(ctx);
	if (ssl == NULL)
		goto err;

	if (hostname && *hostname) {
		if (SSL_set_tlsext_host_name(ssl, hostname) != 1)
			goto err;
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
		X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		if (X509_VERIFY_PARAM_set1_host(param, hostname, 0) != 1)
			goto err;
#endif
	}

	if (SSL_set_fd(ssl, fd) != 1)
		goto err;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		goto err;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		goto err;

	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
	while (1) {
		rc = SSL_connect(ssl);
		if (rc == 1)
			break;
		switch (SSL_get_error(ssl, rc)) {
		case SSL_ERROR_WANT_READ:
			if (tls_wait_fd(fd, 0, &tv))
				goto err;
			break;
		case SSL_ERROR_WANT_WRITE:
			if (tls_wait_fd(fd, 1, &tv))
				goto err;
			break;
		default:
			goto err;
		}
	}

	if (fcntl(fd, F_SETFL, flags) == -1)
		goto err;

	if (SSL_get_verify_result(ssl) != X509_V_OK)
		goto err;

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		goto err;
	entry->fd = fd;
	entry->ssl = ssl;
	entry->ctx = ctx;
	entry->next = tls_head;
	tls_head = entry;
	return 0;

err:
	if (ssl)
		SSL_free(ssl);
	if (ctx)
		SSL_CTX_free(ctx);
	errno = EPROTO;
	return -1;
#else
	(void)fd;
	(void)hostname;
	(void)timeout_ms;
	errno = ENOSYS;
	return -1;
#endif
}

int net_has_pending(int fd)
{
#if HAVE_OPENSSL
	struct tls_entry *entry = tls_find(fd);
	if (entry == NULL)
		return 0;
	return SSL_pending(entry->ssl) > 0;
#else
	(void)fd;
	return 0;
#endif
}

ssize_t net_read(int fd, void *buf, size_t count)
{
#if HAVE_OPENSSL
	struct tls_entry *entry = tls_find(fd);
	if (entry) {
		int rc = SSL_read(entry->ssl, buf, (int)count);
		if (rc > 0)
			return rc;
		switch (SSL_get_error(entry->ssl, rc)) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			errno = EAGAIN;
			return -1;
		case SSL_ERROR_ZERO_RETURN:
			return 0;
		default:
			errno = EIO;
			return -1;
		}
	}
#endif
	return read(fd, buf, count);
}

ssize_t net_write(int fd, const void *buf, size_t count)
{
#if HAVE_OPENSSL
	struct tls_entry *entry = tls_find(fd);
	if (entry) {
		int rc = SSL_write(entry->ssl, buf, (int)count);
		if (rc > 0)
			return rc;
		switch (SSL_get_error(entry->ssl, rc)) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			errno = EAGAIN;
			return -1;
		default:
			errno = EIO;
			return -1;
		}
	}
#endif
	return write(fd, buf, count);
}

off_t net_lseek(int fd, off_t offset, int whence)
{
#if HAVE_OPENSSL
	if (tls_find(fd)) {
		errno = ESPIPE;
		return -1;
	}
#endif
	return lseek(fd, offset, whence);
}

int net_close(int fd)
{
#if HAVE_OPENSSL
	struct tls_entry *entry = tls_find(fd);
	if (entry) {
		SSL_shutdown(entry->ssl);
		SSL_free(entry->ssl);
		SSL_CTX_free(entry->ctx);
		tls_remove(entry);
		free(entry);
	}
#endif
	return close(fd);
}
