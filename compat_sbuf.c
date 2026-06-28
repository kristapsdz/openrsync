/*
 * Copyright (c) Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#if !HAVE_SBUF

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "compat_sbuf.h"

struct sbuf *
sbuf_new_auto(void)
{
	return calloc(1, sizeof(struct sbuf));
}

int
sbuf_cat(struct sbuf *s, const char *buf)
{
	return sbuf_bcat(s, buf, strlen(buf));
}

size_t
sbuf_len(struct sbuf *s)
{
	return s == NULL ? 0 : s->len;
}

int
sbuf_bcat(struct sbuf *s, const void *buf, size_t len)
{
	void	*pp;

	if (s == NULL)
		return -1;

	pp = realloc(s->buf, s->len + len);
	if (pp == NULL)
		return -1;
	s->buf = pp;
	memcpy(s->buf + s->len, buf, len);
	s->len += len;
	return 0;
}

const char *
sbuf_data(struct sbuf *s)
{
	return s == NULL ? NULL : s->buf;
}

void
sbuf_delete(struct sbuf *s)
{
	if (s == NULL)
		return;
	free(s->buf);
	free(s);
}

int
sbuf_printf(struct sbuf *s, const char *fmt, ...)
{
	va_list	 ap;
	char	*buf;
	int	 rc, len;

	if (s == NULL)
		return -1;

	va_start(ap, fmt);
	if ((len = vasprintf(&buf, fmt, ap)) == -1) {
		va_end(ap);
		return -1;
	}
	va_end(ap);
	rc = sbuf_bcat(s, buf, len);
	free(buf);
	return rc;
}

int
sbuf_putc(struct sbuf *s, int c)
{
	char	 cc = c;

	return sbuf_bcat(s, &cc, 1);
}

int
sbuf_finish(struct sbuf *s)
{
	if (s == NULL)
		return -1;
	if (s->len && s->buf[s->len - 1] == '\0')
		return 0;
	return sbuf_putc(s, '\0');
}

#endif /* !HAVE_SBUF */
