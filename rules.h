/*
 * Copyright (c) 2021 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2024 Klara, Inc.
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
#ifndef RULES_H
#define RULES_H

/*
 * Types of rules that may appear for directories or files.
 */
enum rule_type {
	RULE_NONE,
	RULE_EXCLUDE,
	RULE_INCLUDE,
	RULE_CLEAR,
	RULE_MERGE,
	RULE_DIR_MERGE,
	RULE_SHOW,
	RULE_HIDE,
	RULE_PROTECT,
	RULE_RISK,
};

int	parse_rule(const char *line, enum rule_type, char);
void	parse_file_rule(const char *, enum rule_type, char);
void	send_rules(struct sess *, int);
void	recv_rules(struct sess *, int);
int  	rules_match(const char *, bool, enum fmode, bool);
void	rules_base(const char *);
void	rules_dir_push(const char *, size_t, int);
void	rules_dir_pop(const char *, size_t);

#endif /*!RULES_H*/
