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
#ifndef SBUF_H
#define SBUF_H

#if !HAVE_SBUF

struct sbuf {
	char	*buf;
	size_t	 len;
};

struct sbuf *sbuf_new_auto(void);

size_t sbuf_len(struct sbuf *s);

int sbuf_cat(struct sbuf *s, const char *buf);

int sbuf_bcat(struct sbuf *s, const void *buf, size_t len);

const char *sbuf_data(struct sbuf *s);

void sbuf_delete(struct sbuf *s);

int sbuf_printf(struct sbuf *s, const char *fmt, ...);

int sbuf_putc(struct sbuf *s, int c);

int sbuf_finish(struct sbuf *s);

#endif /* !HAVE_SBUF */
#endif /* !SBUF_H */
