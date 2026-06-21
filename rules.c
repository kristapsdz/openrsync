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
#include "config.h"

#include <sys/param.h>
#if HAVE_SYS_QUEUE
# include <sys/queue.h>
#endif
#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#if HAVE_ERR
# include <err.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "extern.h"
#include "rules.h"

struct rule;

struct ruleset {
	struct ruleset		*parent_set;
	struct rule		*rules;
	size_t			 lclear; /* latest clear rule */
	size_t			 numrules; /* number of rules */
	size_t			 rulesz; /* available size */
#ifndef NDEBUG
	size_t		 	 numdrules; /* number of dir-merge rules */
#endif
};

struct merge_rule {
	TAILQ_ENTRY(merge_rule)	 entries;
	struct rule		*parent_rule;
	struct ruleset		*ruleset;
	char			*path;
	size_t			 depth;
	bool			 inherited;
};

TAILQ_HEAD(merge_ruleq, merge_rule);

struct rule {
	struct merge_ruleq	 merge_rule_chain;
	char			*pattern;
	enum rule_type		 type;
	unsigned int		 omodifiers;
	unsigned int		 modifiers;
	short			 numseg;
	bool			 anchored;
	bool			 fileonly;
	bool			 nowild;
	bool			 onlydir;
	bool			 leadingdir;
};

struct rule_match_ctx {
	char			 abspath[PATH_MAX];
	const char		*basename;
	bool			 isdir;
	bool			 perishing;
	int			 match;
	enum fmode		 rulectx;
};

struct rule_dir_ctx {
	size_t			 stripdir;
	int			 delim;
};

enum rule_iter_action {
	RULE_ITER_HALT, /* halt iteration entirely */
	RULE_ITER_HALT_CHAIN, /* halt this merge chain */
	RULE_ITER_SKIP, /* skip further processing of this rule */
	RULE_ITER_CONTINUE, /* continue as normal */
};

/* FIXME: can the rule and ruleset not be const? */
typedef enum rule_iter_action (rule_iter_fn)(struct ruleset *,
    struct rule *, const char *, void *);

struct rule_export_ctx {
	arglist			*args;
	const struct sess	*sess;
};

static char 		 rule_base[MAXPATHLEN];
static char		*rule_base_cwdend;

static struct ruleset global_ruleset = {
	.lclear = (size_t)-1,
};

static size_t rule_dir_depth;

static void parse_file_impl(struct ruleset *, const char *, enum rule_type,
    unsigned int, bool, char);
static bool parse_rule_impl(struct ruleset *, const char *, enum rule_type,
    unsigned int, char);

/* up to protocol 29 filter rules only support - + ! and no modifiers */

const struct command {
	enum rule_type		type;
	char			sopt;
	const char		*lopt;
} commands[] = {
	{ RULE_EXCLUDE,		'-',	"exclude" },
	{ RULE_INCLUDE,		'+',	"include" },
	{ RULE_CLEAR,		'!',	"clear" },
	{ RULE_MERGE,		'.',	"merge" },
	{ RULE_DIR_MERGE,	':',	"dir-merge" },
	{ RULE_SHOW,		'S',	"show" },
	{ RULE_HIDE,		'H',	"hide" },
	{ RULE_PROTECT,		'P',	"protect" },
	{ RULE_RISK,		'R',	"risk" },
	{ 0 }
};

#define MOD_ABSOLUTE			0x0001
#define MOD_NEGATE			0x0002
#define MOD_CVSEXCLUDE			0x0004
#define MOD_SENDING			0x0008
#define MOD_RECEIVING			0x0010
#define MOD_PERISHABLE			0x0020
#ifdef NOTYET
#define MOD_XATTR			0x0040
#endif
#define MOD_MERGE_EXCLUDE		0x0080
#define MOD_MERGE_INCLUDE		0x0100
#define MOD_MERGE_CVSCOMPAT		0x0200
#define MOD_MERGE_EXCLUDE_FILE		0x0400
#define MOD_MERGE_NO_INHERIT		0x0800
#define MOD_MERGE_WORDSPLIT		0x1000

#define MOD_SENDRECV_MASK		(MOD_SENDING | MOD_RECEIVING)

#define MOD_MERGE_MASK			0x1f80
#define MOD_VALID_MASK			0x1fff

/* maybe support absolute and negate */
const struct modifier {
	unsigned int		modifier;
	char			sopt;
} modifiers[] = {
	{ MOD_ABSOLUTE,			'/' },
	{ MOD_NEGATE,			'!' },
	{ MOD_CVSEXCLUDE | MOD_MERGE_CVSCOMPAT,		'C' },
	{ MOD_SENDING,			's' },
	{ MOD_RECEIVING,		'r' },
	{ MOD_PERISHABLE,		'p' },
#ifdef NOTYET
	{ MOD_XATTR,			'x' },
#endif
	/* for '.' and ':' types */
	{ MOD_MERGE_EXCLUDE,		'-' },
	{ MOD_MERGE_INCLUDE,		'+' },
	{ MOD_MERGE_EXCLUDE_FILE,	'e' },
	{ MOD_MERGE_NO_INHERIT,		'n' },
	{ MOD_MERGE_WORDSPLIT,		'w' },
	{ 0 }
};

static struct rule *
get_next_rule(struct ruleset *ruleset)
{
	struct rule *new;
	size_t newsz;

	if (++ruleset->numrules > ruleset->rulesz) {
		if (ruleset->rulesz == 0)
			newsz = 16;
		else
			newsz = ruleset->rulesz * 2;

		new = recallocarray(ruleset->rules, ruleset->rulesz, newsz,
		    sizeof(*ruleset->rules));
		if (new == NULL)
			err(ERR_NOMEM, NULL);

		ruleset->rules = new;
		ruleset->rulesz = newsz;
	}

	return ruleset->rules + ruleset->numrules - 1;
}

static unsigned int
parse_modifiers(const char *command, size_t *len)
{
	unsigned int modmask, modparsed;
	size_t idx;
	char mod;

	modmask = 0;
	for (idx = 0; idx < *len; idx++) {
		mod = command[idx];

		modparsed = 0;
		for (size_t i = 0; modifiers[i].modifier != 0; i++) {
			if (modifiers[i].sopt == mod) {
				modparsed = modifiers[i].modifier;
				break;
			}
		}

		if (modparsed == 0)
			break;

		modmask |= modparsed;
	}

	*len -= idx;

	return modmask;
}

static enum rule_type
parse_command(const char *command, size_t len, unsigned int *omodifiers)
{
	const struct command *cmd;
	const char *mod;
	size_t	cmdlen, i;
	unsigned int modifiers;

	/* Command has been omitted, short-circuit. */
	if (len == 0)
		return RULE_NONE;

	cmd = NULL;
	cmdlen = len;

	mod = memchr(command, ',', cmdlen);
	if (mod != NULL) {
		cmdlen = mod - command;
		mod++;
	}

	/*
	 * Do a pass up front to figure out the command.  We don't need to use
	 * cmdlen to check for short names because they're designed to not
	 * conflict with the first character of any long name.
	 */
	for (i = 0; commands[i].type != RULE_NONE; i++) {
		if (strncmp(commands[i].lopt, command, cmdlen) == 0) {
			cmd = &commands[i];
			break;
		} else if (commands[i].sopt == *command) {
			cmd = &commands[i];

			/*
			 * The comma separator for modifiers is optional if a
			 * short name is used, so point mod in the right
			 * direction if there was no comma in the rule string.
			 */
			if (mod == NULL && command[1] != '\0')
				mod = &command[1];
			break;
		}
	}

	if (cmd == NULL)
		return RULE_NONE;

	modifiers = 0;
	if (mod != NULL) {
		size_t modlen;

		modlen = len - (mod - command);
		modifiers = parse_modifiers(mod, &modlen);

		/* Some modifier could not be processed. */
		if (modlen != 0)
			return RULE_NONE;
	}

	if (omodifiers != NULL)
		*omodifiers = modifiers;
	return cmd->type;
}

static void
parse_pattern(struct rule *r, char *pattern)
{
	size_t plen;
	char *p;
	short nseg = 1;

	/*
	 * check for / at start and end of pattern both are special and
	 * can bypass full path matching.
	 */
	plen = strlen(pattern);
	if (*pattern == '/') {
		/*
		 * Note that it's anchored and omit the leading slash.  We have
		 * to keep `pattern` intact as it's allocated memory.
		 */
		plen--;
		memmove(pattern, pattern + 1, plen + 1 /* NUL */);
		r->anchored = true;
	}

	/*
	 * check for patterns ending in '/' and '/'+'***' and handle them
	 * specially. Because of this and the check above pattern will never
	 * start or end with a '/'.
	 */
	if (plen > 1 && pattern[plen - 1] == '/') {
		r->onlydir = true;
		pattern[plen - 1] = '\0';
	}
	if (!r->onlydir && plen > 4 &&
	    strcmp(pattern + plen - 4, "/***") == 0) {
		r->leadingdir = true;
		pattern[plen - 4] = '\0';
	}

	/* count how many segments the pattern has. */
	for (p = pattern; *p != '\0'; p++)
		if (*p == '/')
			nseg++;
	r->numseg = nseg;

	/* check if this pattern only matches against the basename */
	if (nseg == 1 && !r->anchored && !r->leadingdir)
		r->fileonly = true;

	if (strpbrk(pattern, "*?[") == NULL) {
		/* no wildchar matching */
		r->nowild = true;
	} else {
		/* requires wildchar matching */
		if (strstr(pattern, "**") != NULL)
			r->numseg = -1;
	}

	r->pattern = pattern;
}

static bool
modifiers_valid(enum rule_type rule, unsigned int *modifiers)
{
	unsigned int valid_mask;

	switch (rule) {
	case RULE_DIR_MERGE:
	case RULE_MERGE:
		if ((*modifiers & (MOD_MERGE_EXCLUDE | MOD_MERGE_INCLUDE)) ==
		    (MOD_MERGE_EXCLUDE | MOD_MERGE_INCLUDE))
			return false;
		valid_mask = MOD_VALID_MASK;
		break;
	case RULE_EXCLUDE:
	case RULE_INCLUDE:
	case RULE_SHOW:
	case RULE_HIDE:
	case RULE_RISK:
	case RULE_PROTECT:
		valid_mask = MOD_VALID_MASK & ~MOD_MERGE_MASK;
		break;
	default:
		valid_mask = 0;
		break;
	}

	*modifiers &= valid_mask;
	return (true);
}

static int
pattern_valid(enum rule_type rule, unsigned int modifiers, const char *pattern)
{
	bool is_empty, need_empty = false;

	switch (rule) {
	case RULE_EXCLUDE:
		if ((modifiers & MOD_CVSEXCLUDE) == 0)
			break;
		/* FALLTHROUGH */
	case RULE_CLEAR:
		need_empty = true;
		break;
	default:
		break;
	}

	is_empty = *pattern == '\0';
	return is_empty == need_empty;
}

static enum rule_type
rule_modified(enum rule_type rule, unsigned int *modifiers)
{
	unsigned int mod = *modifiers;

	if (mod == 0)
		return rule;

	switch (rule) {
	case RULE_EXCLUDE:
		if ((mod & MOD_SENDRECV_MASK) == MOD_SENDRECV_MASK) {
			/* Just unset the modifiers. */
		} else if ((mod & MOD_SENDING) != 0) {
			rule = RULE_HIDE;
		} else if ((mod & MOD_RECEIVING) != 0) {
			rule = RULE_PROTECT;
		}

		/* FALLTHROUGH */
	case RULE_HIDE:
	case RULE_PROTECT:
		/*
		 * For all of the include/exclude rules, send/recv modifiers
		 * don't make any sense and should be stripped.
		 */
		mod &= ~MOD_SENDRECV_MASK;
		break;
	case RULE_INCLUDE:
		if ((mod & MOD_SENDRECV_MASK) == MOD_SENDRECV_MASK) {
			/* Just unset the modifiers. */
		} else if ((mod & MOD_SENDING) != 0) {
			rule = RULE_SHOW;
		} else if ((mod & MOD_RECEIVING) != 0) {
			rule = RULE_RISK;
		}

		/* FALLTHROUGH */
	case RULE_SHOW:
	case RULE_RISK:
		mod &= ~MOD_SENDRECV_MASK;
		break;
	case RULE_MERGE:
	case RULE_DIR_MERGE:
		/*
		 * We can't zap any modifiers for merge rules; they need to be
		 * either inherited or just enacted for the merge directive on
		 * the other side.
		 */
		return rule;
	default:
		/* Zap modifiers for everything else; inherited, not needed. */
		mod = 0;
		break;
	}

	*modifiers = mod;
	return rule;
}

static bool
add_cvsignore_rules(void)
{
	char 		  home_cvsignore[PATH_MAX];
	const char	 *cvsignore, *home;
	bool		  ret;
	static const char builtin_cvsignore[] =
		"RCS SCCS CVS CVS.adm RCSLOG cvslog.* tags "
		"TAGS .make.state .nse_depinfo *~ #* .#* ,* "
		"_$* *$ *.old *.bak *.BAK *.orig *.rej .del-* "
		"*.a *.olb *.o *.obj *.so *.exe *.Z *.elc "
		"*.ln core "
		".svn/ ";

	/* XXX shouldn't transfer any of these? */
	/* First we add the internal cvsignore rules. */

	ret = parse_rule_impl(&global_ruleset, builtin_cvsignore,
	    RULE_EXCLUDE, MOD_MERGE_WORDSPLIT, '\n');
	if (!ret)
		return ret;

	/* Next we process ~/.cvsignore */

	home = getenv("HOME");

	if (home != NULL && *home != '\0') {
		if (snprintf(home_cvsignore, sizeof(home_cvsignore),
		    "%s/.cvsignore", home) < (int)sizeof(home_cvsignore))
			parse_file_impl(&global_ruleset, home_cvsignore,
			    RULE_EXCLUDE, MOD_MERGE_WORDSPLIT, false, '\n');
	}

	/*
	 * Finally, we process the CVSIGNORE environment var for more
	 * files.
	 */

	cvsignore = getenv("CVSIGNORE");
	if (cvsignore != NULL && *cvsignore != '\0')
		ret = parse_rule_impl(&global_ruleset, cvsignore,
		    RULE_EXCLUDE, MOD_MERGE_WORDSPLIT, '\n');

	return ret;
}

static void
ruleset_add_merge(struct ruleset *ruleset)
{
#ifndef NDEBUG
	struct ruleset *rs = ruleset;
	do {
		rs->numdrules++;
	} while ((rs = rs->parent_set) != NULL);
#endif
}

static void
ruleset_remove_merge(struct ruleset *ruleset)
{
#ifndef NDEBUG
	struct ruleset *rs = ruleset;
	do {
		assert(rs->numdrules != 0);
		rs->numdrules--;
	} while ((rs = rs->parent_set) != NULL);
#endif
}

static void
ruleset_free(struct ruleset *ruleset)
{
	struct rule	*r;
	size_t		 i;

	for (i = 0; i < ruleset->numrules; i++) {
		r = &ruleset->rules[i];
		if (r->type == RULE_DIR_MERGE) {
			assert(ruleset->numdrules > 0);
			assert(ruleset->parent_set->numdrules > 0);
			/*
			 * We should only be attempting to remove a
			 * dir-merge rule if it doesn't have any active
			 * directories left.
			 */
			assert(TAILQ_EMPTY(&r->merge_rule_chain));
			ruleset_remove_merge(ruleset);
		}
		free(r->pattern);
	}

	assert(ruleset->numdrules == 0);
	free(ruleset->rules);
	free(ruleset);
}

static void
ruleset_do_merge(struct ruleset *ruleset, const char *path,
    int modifiers, char delim)
{
	enum rule_type def;

	if ((modifiers & MOD_MERGE_EXCLUDE) != 0)
		def = RULE_EXCLUDE;
	else if ((modifiers & MOD_MERGE_INCLUDE) != 0)
		def = RULE_INCLUDE;
	else
		def = RULE_NONE;

	parse_file_impl(ruleset, path, def, modifiers, true, delim);
}

/*
 * Parses the line for a rule with consideration for the inherited
 * modifiers.
 * Return true on success, false on failure.
 */
static bool
parse_rule_impl(struct ruleset *ruleset, const char *line,
    enum rule_type def, unsigned int imodifiers, char delim)
{
	struct rule	*r;
	const char	*pstart, *pend;
	char		*pattern;
	enum rule_type	 type;
	size_t		 len;
	unsigned int	 modifiers;
	const bool	 wsplit = (imodifiers & MOD_MERGE_WORDSPLIT);

	imodifiers &= ~MOD_MERGE_MASK;
	modifiers = 0;

	/* Empty lines are ignored. */
	while (*line != '\0') {
		if (wsplit) {
			while (isspace(*line))
				line++;
		}

		type = RULE_NONE;
		switch (*line) {
		case '\0':
			/* ignore empty lines */
			return true;
		case '#':
		case ';':
			/* Comments, but they are disabled in word split mode */
			if (!wsplit)
				return true;
			/* FALLTHROUGH */
		default:
			modifiers = 0;
			if (def == RULE_NONE ||
			    strncmp(line, "- ", 2) == 0 ||
			    strncmp(line, "+ ", 2) == 0 ||
			    strcmp(line, "!") == 0) {
				len = strcspn(line, " _");
				type = parse_command(line, len, &modifiers);
			}

			if (type == RULE_NONE) {
				if (def == RULE_NONE)
					return false;
				type = def;
				pstart = line;
			} else {
				/*
				 * Some available rules have no arguments, so
				 * we're pointing at the NUL byte and we
				 * shouldn't walk past that.
				 */
				pstart = line + len;
				if (*pstart != '\0')
					pstart++;
			}

			/*
			 * Merge rules and non-merge rules share 'C' as a common
			 * modifier between the two, so it just sets both bits.
			 * Untangle it here.
			 */
			if (type == RULE_MERGE || type == RULE_DIR_MERGE)
				modifiers &= ~MOD_CVSEXCLUDE;
			else
				modifiers &= ~MOD_MERGE_CVSCOMPAT;

			if (!modifiers_valid(type, &modifiers))
				return false;

			/* Make a copy of the pattern */
			pend = pstart;
			if (wsplit) {
				while (!isspace(*pend) && *pend != '\0') {
					pend++;
				}
			} else {
				pend = pstart + strlen(pstart);
			}

			line = pend;
			if (pend == pstart && type == RULE_DIR_MERGE &&
			    (modifiers & MOD_MERGE_CVSCOMPAT) != 0) {
				pattern = strdup(".cvsignore");
			} else {
				pattern = strndup(pstart, pend - pstart);
			}
			if (pattern == NULL)
				err(ERR_NOMEM, "strndup");

			if (!pattern_valid(type, modifiers, pattern)) {
				free(pattern);
				return false;
			}

			/*
			 * The CVS compat modifier turns on 'n', 'w', and '-'.
			 */
			if (type == RULE_DIR_MERGE &&
			    (modifiers & MOD_MERGE_CVSCOMPAT) != 0) {
				modifiers |= MOD_MERGE_NO_INHERIT |
				    MOD_MERGE_WORDSPLIT | MOD_MERGE_EXCLUDE;
			}

			/*
			 * We inherit the modifiers here to bypass the validity
			 * check, but we want them to be considered in
			 * rule_modified() in case we need to promote some
			 * rules.  There's a good chance it will simply zap most
			 * of the modifiers and send us on our way.
			 */
			modifiers |= imodifiers;
			if (modifiers != 0)
				type = rule_modified(type, &modifiers);
			break;
		}

		r = get_next_rule(ruleset);
		TAILQ_INIT(&r->merge_rule_chain);
		r->type = type;
		r->omodifiers = r->modifiers = modifiers;
		if (type == RULE_MERGE || type == RULE_DIR_MERGE)
			r->modifiers &= MOD_MERGE_MASK;
		if (type == RULE_CLEAR)
			ruleset->lclear = r - ruleset->rules;

		/*
		 * Merge rules are processed just once and may be an absolute
		 * path, while dir-merge rules are processed once per directory
		 * we traverse in the transfer.
		 */
		if (type == RULE_MERGE)
			r->pattern = pattern;
		else
			parse_pattern(r, pattern);

		if (type == RULE_MERGE || type == RULE_DIR_MERGE)
			if (modifiers & MOD_MERGE_EXCLUDE_FILE)
				if (!parse_rule_impl(ruleset, r->pattern,
				    RULE_EXCLUDE, 0, delim))
					return false;

		if (type == RULE_MERGE)
			ruleset_do_merge(ruleset, r->pattern,
			    modifiers, delim);
		else if (type == RULE_DIR_MERGE)
			ruleset_add_merge(ruleset);
		else if (modifiers & MOD_CVSEXCLUDE)
			add_cvsignore_rules();

		pattern = NULL;
	}

	return true;
}

bool
parse_rule(const char *line, enum rule_type def, char delim)
{
	return parse_rule_impl(&global_ruleset, line, def, 0, delim);
}

/*
 * FIXME: this will not work because it happens after unveil.
 */
static void
parse_file_impl(struct ruleset *ruleset, const char *file, enum rule_type def,
    unsigned int imodifiers, bool must_exist, char delim)
{
	FILE	*fp; /* the file itself */
	char	*line = NULL; /* current line */
	size_t	 linesize = 0, linenum = 0; /* getdelim() params */
	ssize_t	 linelen; /* getdelim() result */

	if (strcmp(file, "-") == 0) {
		fp = stdin;
	} else if ((fp = fopen(file, "r")) == NULL) {
		if (errno == ENOENT && !must_exist)
			return;
		err(ERR_SYNTAX, "open: %s", file);
	}

	while ((linelen = getdelim(&line, &linesize, delim, fp)) != -1) {
		linenum++;
		line[linelen - 1] = '\0';
		if (!parse_rule_impl(ruleset, line, def, imodifiers, delim))
			errx(ERR_SYNTAX, "syntax error in %s at entry %zu",
			    file, linenum);
	}

	free(line);
	if (ferror(fp))
		err(ERR_SYNTAX, "failed to parse file %s",
		    fp == stdin ? "stdin" : file);
	if (fp != stdin)
		fclose(fp);
}

void
parse_file_rule(const char *file, enum rule_type def, char delim)
{
	parse_file_impl(&global_ruleset, file, def, 0, true, delim);
}

/*
 * Translate the given rule "r" into a sendable rule.
 * If the command cannot be translated due to protocol compatibility,
 * this returns NULL; otherwise, it returns the translated rule.
 */
static const char *
send_command(const struct sess *sess, const struct rule *r)
{
	static char	 buf[16]; /* send buffer */
	char 		*b = buf; /* current position */
	const char 	*ep = buf + sizeof(buf); /* end pointer */

	switch (r->type) {
	case RULE_EXCLUDE:
		*b++ = '-';
		break;
	case RULE_INCLUDE:
		*b++ = '+';
		break;
	case RULE_CLEAR:
		*b++ = '!';
		break;
	case RULE_MERGE:
		*b++ = '.';
		break;
	case RULE_DIR_MERGE:
		*b++ = ':';
		break;
	case RULE_SHOW:
		*b++ = 'S';
		break;
	case RULE_HIDE:
		*b++ = 'H';
		break;
	case RULE_PROTECT:
		*b++ = 'P';
		break;
	case RULE_RISK:
		*b++ = 'R';
		break;
	default:
		err(ERR_SYNTAX, "unknown rule type %d", r->type);
	}

	for (int i = 0; modifiers[i].modifier != 0; i++) {
		if (r->omodifiers & modifiers[i].modifier)
			*b++ = modifiers[i].sopt;
		if (b >= ep - 3)
			err(ERR_SYNTAX, "rule modifiers overflow");
	}
	if (b >= ep - 3)
		err(ERR_SYNTAX, "rule prefix overflow");
	*b++ = ' ';

	/* include the stripped root '/' for anchored patterns */
	if (r->anchored)
		*b++ = '/';
	*b++ = '\0';
	return buf;
}

/*
 * If the rule is onlydir or leaderdir, append the correct directory
 * specifier and return that.  Otherwise, return an empty string.
 */
static const char *
postfix_command(const struct rule *r)
{
	static char buf[8];

	buf[0] = '\0';
	if (r->onlydir)
		strlcpy(buf, "/", sizeof(buf));
	if (r->leadingdir)
		strlcpy(buf, "/***", sizeof(buf));

	return buf;
}

/*
 * Check if the rule should be sent.  This will filter out those rules
 * only applicable to the receiver/sender.
 */
static bool
rule_should_xfer(const struct sess *sess, const struct rule *r)
{
	bool	 res = true;

	/*
	 * Merge files without the include/exclude modifiers get passed
	 * through for compatibility.
	 */

	if (r->type == RULE_MERGE)
		res = !(r->modifiers & (MOD_MERGE_EXCLUDE | MOD_MERGE_INCLUDE));

	/*
	 * If *we* are the sender, the other side is mostly interested
	 * in exclusion rules for the purposes of --delete-excluded.
	 */

	if (sess->mode == FARGS_SENDER)
		switch (r->type) {
		case RULE_INCLUDE:
		case RULE_EXCLUDE:
		case RULE_PROTECT:
		case RULE_RISK:
			/* Explicitly receiver-side rules */
			res = true;
			break;
		default:
			res = false;
			break;
		}

	/* We don't send non-merge rules when del_excl is enabled. */

	if (sess->opts->del_excl && sess->mode == FARGS_SENDER &&
	    r->type != RULE_MERGE)
		res = false;

	return res;
}

/*
 * Send the list of global rules.  The list is narrowed to the rules
 * that can be processed by the other side.  The check_send_rules()
 * function should be called beforehand.
 * FIXME: this should return a failure code and not just exit.
 */
void
send_rules(struct sess *sess, int fd)
{
	const char	*cmd, /* string version of rule */
			*postfix; /* string suffix */
	struct rule 	*r; /* rule to send */
	size_t		 cmdlen, /* length of cmd */
			 len, /* length of rule pattern */
			 postlen, /* length of postfix */
			 i; /* temporary index */
	int		 writelen; /* write length */

	for (i = 0; i < global_ruleset.numrules; i++) {
		r = &global_ruleset.rules[i];

		if (!rule_should_xfer(sess, r))
			continue;

		cmd = send_command(sess, r);
		assert(cmd != NULL);
		postfix = postfix_command(r);
		cmdlen = strlen(cmd);
		len = strlen(r->pattern);
		postlen = strlen(postfix);

		/* Write: [flist-rule-len]. */

		writelen = (int)(cmdlen + len + postlen);
		if (!io_write_int(sess, fd, writelen))
			err(ERR_SOCK_IO, "send rules");

		/* Write: [flist-rule]. */

		if (!io_write_buf(sess, fd, cmd, cmdlen))
			err(ERR_SOCK_IO, "send rules");
		if (!io_write_buf(sess, fd, r->pattern, len))
			err(ERR_SOCK_IO, "send rules");
		/* include the '/' stripped by onlydir */
		if (postlen > 0)
			if (!io_write_buf(sess, fd, postfix, postlen))
				err(ERR_SOCK_IO, "send rules");
	}

	/* Write: [flist-rule-len] (exit). */

	if (!io_write_int(sess, fd, 0))
		err(ERR_SOCK_IO, "send rules");
}

void
check_send_rules(const struct sess *sess)
{
	struct rule 	*r; /* rule to send */
	size_t		 i; /* temporary */

	for (i = 0; i < global_ruleset.numrules; i++) {
		r = &global_ruleset.rules[i];
		if (r->type == RULE_DIR_MERGE && sess->protocol < 29)
			errx(ERR_PROTOCOL, "rules are incompatible with "
			    "remote rsync");
	}
}

/*
 * + rules are sent without the command in some circumstances, so see if we have
 * what looks like an unsalted exclude rule.
 */
static enum rule_type
rule_xfer_type(const char **linep, unsigned int *modifiers)
{
	const char *line = *linep;
	size_t len;
	enum rule_type type;
	unsigned int cmods;

	len = strcspn(line, " _");

	/*
	 * Not completely sure... see if this matches one of our rule prefixes.
	 * If it doesn't, we have to assume that it's an exclude rule.
	 */
	type = parse_command(line, len, &cmods);
	if (type != RULE_NONE) {
		*linep = line + len + 1;
		*modifiers = cmods;
	} else {
		type = RULE_EXCLUDE;
	}

	return type;
}

/*
 * Read the filter rules.
 * FIXME: this should return a failure code and not just exit.
 */
void
recv_rules(struct sess *sess, int fd)
{
	char		 line[8192]; /* buffer of maximum filter size */
	char		*rule; /* pointer to line */
	size_t		 len; /* length of line */
	enum rule_type	 type; /* parsed type */
	unsigned int	 modifiers; /* parsed modifiers */

	do {
		/* Read: [flist-rule-len]. */

		if (!io_read_size(sess, fd, &len))
			err(ERR_SOCK_IO, "receive rules");
		if (len == 0)
			return;
		if (len >= sizeof(line) - 1)
			errx(ERR_SOCK_IO, "received rule too long");

		/* Read: [flist-rule]. */

		if (!io_read_buf(sess, fd, line, len))
			err(ERR_SOCK_IO, "receive rules");
		line[len] = '\0';

		rule = &line[0];
		modifiers = 0;
		type = rule_xfer_type((const char **)&rule, &modifiers);
		if (!parse_rule_impl(&global_ruleset, rule, type,
		    modifiers, '\0'))
			errx(ERR_PROTOCOL, "syntax error in received rules");
	} while (1);
}

static inline bool
rule_actionable(const struct rule *r, enum fmode rulectx, bool perishing)
{
	/*
	 * If we encounter a clear rule, that means we didn't catch the
	 * latest clear rule, or we did something else wrong.
	 */
	assert(r->type != RULE_CLEAR);

	if ((r->modifiers & MOD_PERISHABLE) != 0 && perishing)
		return false;

	switch (r->type) {
	/* Almost always actionable */
	case RULE_EXCLUDE:
		if ((r->modifiers & MOD_CVSEXCLUDE) != 0)
			return false;
		/* FALLTHROUGH */
	case RULE_INCLUDE:
		return true;
	/* Sender side */
	case RULE_HIDE:
	case RULE_SHOW:
		if (rulectx == FARGS_SENDER)
			return true;
		break;
	/* Receiver side */
	case RULE_PROTECT:
	case RULE_RISK:
		if (rulectx == FARGS_RECEIVER)
			return true;
		break;
	/* Meta, never actionable */
	case RULE_CLEAR:
	case RULE_MERGE:
	case RULE_DIR_MERGE:
	default:
		break;
	}

	return false;
}

/*
 * Decompose the rule into -1 (hides, protects, excludes) or 1 (shows,
 * risks, includes).
 */
static inline int
rule_matched(const struct rule *r)
{
	int	 ret = 0;

	/*
	 * We decomposed RULE_EXCLUDE and RULE_INCLUDE based on
	 * sender/receiver modifiers earlier on, so we don't need to
	 * check it again here.  We won't see hide/show/protect/risk
	 * rules here unless we're on the appropriate side, so we don't
	 * need to worry about that, either.
	 */

	switch (r->type) {
	case RULE_HIDE:
	case RULE_PROTECT:
	case RULE_EXCLUDE:
		ret = -1;
		break;
	case RULE_SHOW:
	case RULE_RISK:
	case RULE_INCLUDE:
		ret = 1;
		break;
	default:
		/* Illegal, should have been filtered out above. */
		break;
	}

	assert(ret != 0);
	return ret;
}

static inline bool
rule_pattern_matched(const struct rule *r, const char *path)
{
	bool	 matched, negate;

	negate = (r->modifiers & MOD_NEGATE) != 0;

	/*
	 * We need to augment this result with the negate modifier; the
	 * intention of the negate modifier is that the rule shoud only
	 * take effect if the pattern did *not* match.  If it *did*
	 * match, then we still need to check other rules for possible
	 * applicability.
	 */

	matched = strcmp(path, r->pattern) == 0;
	return matched != negate;
}

/*
 * Canonicalise a rule path as an absolute path.  THIS FUNCTION WILL
 * EXIT() IF THE FILENAME IS TOO LONG.
 */
static void
rule_abspath(const char *path, char *outpath, size_t outpathsz)
{
	assert(outpathsz >= PATH_MAX);

	if (path[0] == '/') {
		if (strlcpy(outpath, path, outpathsz) >= outpathsz) {
			errno = ENAMETOOLONG;
			err(ERR_FILEGEN, "%s", path);
		}
		return;
	}

	if (strlcpy(outpath, rule_base, outpathsz) >= outpathsz) {
		errno = ENAMETOOLONG;
		err(ERR_FILEGEN, "%s", rule_base);
	}

	/* rule_base is guaranteed to be /-terminated. */

	if (strlcat(outpath, path, outpathsz) >= outpathsz) {
		errno = ENAMETOOLONG;
		err(ERR_FILEGEN, "%s/%s", outpath, path);
	}
}

/*
 * FIXME: what does this do?
 */
void
rules_base(const char *root)
{
	size_t	 slen;

	if (root[0] == '/') {
		if (strlcpy(rule_base, root, sizeof(rule_base)) >=
		    sizeof(rule_base)) {
			errno = ENAMETOOLONG;
			err(ERR_FILEGEN, "strlcpy");
		}
		rule_base_cwdend = NULL;
		return;
	}

	if (rule_base_cwdend == NULL) {
		getcwd(rule_base, sizeof(rule_base) - 1);
		rule_base_cwdend = &rule_base[strlen(rule_base)];
	}

	/*
	 * If we're working with a path within cwd, truncate this back to cwd
	 * so that we can strlcat() it.
	 */

	*rule_base_cwdend = '/';
	*(rule_base_cwdend + 1) = '\0';

	if (strcmp(root, ".") == 0)
		return;

	slen = strlen(root);

	if (strlcat(rule_base, root, sizeof(rule_base)) >= sizeof(rule_base)) {
		errno = ENAMETOOLONG;
		err(ERR_FILEGEN, "strlcat");
	}

	/* Guarantee / termination */

	if (root[slen - 1] != '/' &&
	    strlcat(rule_base, "/", sizeof(rule_base)) >= sizeof(rule_base)) {
		errno = ENAMETOOLONG;
		err(ERR_FILEGEN, "strlcat");
	}
}

/*
 * Returns -1 if the rule matches and is hides, protects, excludes; or 1
 * if it matches and is shows, risks, includes.  Otherwise, return zero.
 */
static int
rule_match_action_xfer(const struct rule *r, const char *path,
    struct rule_match_ctx *ctx)
{
	const char	*p = NULL, *search;
	size_t		 plen, len;
	short		 nseg;
	bool 		 matched, negate;

	if (r->onlydir && !ctx->isdir) {
		/*
		 * Normally we take a neutral stance if the rule was
		 * meant for a directory but we're not matching against
		 * a directory, but if the rule is to be negated then we
		 * inherently do not match it because of the type
		 * mismatch.
		 */
		if ((r->modifiers & MOD_NEGATE) != 0)
			return rule_matched(r);
		return 0;
	}

	/* This should be computed with absolute paths. */

	if ((r->modifiers & MOD_ABSOLUTE) != 0) {
		if (ctx->abspath[0] == '\0')
			rule_abspath(path, ctx->abspath,
			    sizeof(ctx->abspath));
		path = ctx->abspath;
	}

	if (r->nowild) {
		/* fileonly and anchored are mutually exclusive. */

		if (r->fileonly) {
			if (rule_pattern_matched(r, ctx->basename))
				return rule_matched(r);
		} else if (r->leadingdir) {
			plen = strlen(r->pattern);

			p = strstr(path, r->pattern);

			/*
			 * Match from start or dir boundary and also
			 * match to end or to dir boundary.  If we were
			 * anchored, then the start must be at the start.
			 */
			if (r->anchored && p != path)
				return 0;
			if (p != NULL && (p == path || p[-1] == '/') &&
			    (p[plen] == '\0' || p[plen] == '/'))
				return rule_matched(r);
		} else if (r->anchored) {
			/*
			 * assumes that neither path nor pattern
			 * start with a '/'.
			 */
			if (rule_pattern_matched(r, path))
				return rule_matched(r);
		} else {
			len = strlen(path);
			plen = strlen(r->pattern);

			if (len >= plen && rule_pattern_matched(r,
			    path + len - plen)) {
				/* match all or start on dir boundary */
				if (len == plen ||
				    path[len - plen - 1] == '/')
					return rule_matched(r);
			}
		}
	} else if (r->leadingdir && !r->anchored) {
		/*
		 * For ***, we'll start at numsegs + 1 elements from the end
		 * and continue until we've failed to match the whole string.
		 *
		 * Anchored *** is handled below instead, since we'll just do
		 * a standard full path match.
		 */
		nseg = r->numseg - 1;

		p = &path[strlen(path)];
		do {
			p--;
			if (*p == '/' || p == path) {
				search = p;

				if (nseg > 0) {
					nseg--;
					continue;
				}

				/*
				 * Once we've hit the number of segments we
				 * need, we can start matching against all other
				 * delimiters we hit.
				 */
				if (*search == '/')
					search++;
				if (rmatch(r->pattern, search, 1) != 0)
					continue;

				return rule_matched(r);
			}
		} while (p != path);
	} else {
		if (r->fileonly) {
			p = ctx->basename;
		} else if (r->anchored || r->numseg == -1) {
			/* full path matching */
			p = path;
		} else {
			nseg = 1;

			/* match against the last numseg elements */
			for (p = path; *p != '\0'; p++)
				if (*p == '/')
					nseg++;
			if (nseg < r->numseg) {
				p = NULL;
			} else {
				nseg -= r->numseg;
				for (p = path; *p != '\0' && nseg > 0;
				    p++) {
					if (*p == '/')
						nseg--;
				}
			}
		}

		if (p != NULL) {
			negate = (r->modifiers & MOD_NEGATE) != 0;
			matched =  rmatch(r->pattern, p,
			    r->leadingdir) == 0;
			if (matched != negate)
				return rule_matched(r);
		}
	}

	return 0;
}

/*
 * Return true if the given rule "r" has been cleared (i.e., it's before
 * a clear statement).  (If there is no clear statement in the rule set,
 * always returns false.)
 */
static bool
rule_cleared(const struct ruleset *ruleset, const struct rule *r)
{
	assert(r >= ruleset->rules &&
	    r < ruleset->rules + ruleset->numrules);

	if (ruleset->lclear == (size_t)-1)
		return false;
	return (size_t)(r - ruleset->rules) < ruleset->lclear;
}

/*
 * Evaluate a single rule in a ruleset against a path.  Returns
 * RULE_ITER_SKIP if the rule is cleared, RULE_ITER_HALT_CHAIN if there
 * are no more rules (at a clear), RULE_ITER_CONTINUE if the rule isn't
 * actionable or doesn't 
 */
static enum rule_iter_action
rule_match_evaluate(struct ruleset *ruleset, struct rule *r,
    const char *path, void *cookie)
{
	struct rule_match_ctx *ctx = cookie;

	/* If this ruleset has a clear rule in it, skip til we hit. */

	if (rule_cleared(ruleset, r))
		return RULE_ITER_SKIP;

	if (r->type == RULE_CLEAR)
		return RULE_ITER_HALT_CHAIN;

	/* Rule out merge rules and other meta-actions. */

	if (!rule_actionable(r, ctx->rulectx, ctx->perishing))
		return RULE_ITER_CONTINUE;

	ctx->match = rule_match_action_xfer(r, path, ctx);
	if (ctx->match != 0)
		return RULE_ITER_HALT;

	return RULE_ITER_CONTINUE;
}

/*
 * Calls iter_fn on each dir-merge rule that it comes across.  This
 * notably will pick up any new dir-merge rules that get processed in
 * the current directory and issue the callback for it.
 *
 * Popping a directory will want to call the iterator in post-order so
 * that any dir-merge rules nested inside get freed first.
 */
static enum rule_iter_action
rule_iter_impl(struct ruleset *ruleset, const char *path,
    enum rule_type filter, bool postcall, rule_iter_fn *iter_fn,
    void *cookie)
{
	struct merge_rule	*mrule;
	struct rule		*r;
	size_t			 i;
	enum rule_iter_action	 ract = RULE_ITER_CONTINUE;
	bool			 haltchain = false;

	for (i = 0; i < ruleset->numrules; i++) {
		r = &ruleset->rules[i];

		if (filter != RULE_NONE && r->type != filter)
			continue;

		/*
		 * If we're not a dir-merge rule, we might as well call
		 * the callback here regardless of `postcall` since
		 * there is no post-order.
		 */

		ract = RULE_ITER_CONTINUE;
		if (!postcall || r->type != RULE_DIR_MERGE)
			ract = (*iter_fn)(ruleset, r, path, cookie);
		if (ract == RULE_ITER_HALT)
			break;
		else if (ract == RULE_ITER_HALT_CHAIN) {
			/*
			 * We should continue processing this set and
			 * any dir-merge rules contained within it, but
			 * the parent caller should not do any more
			 * chain processing at this level.
			 */
			haltchain = true;
			ract = RULE_ITER_CONTINUE;
		} else if (ract == RULE_ITER_SKIP) {
			ract = RULE_ITER_CONTINUE;
			continue;
		}

		if (r->type != RULE_DIR_MERGE)
			continue;

		TAILQ_FOREACH(mrule, &r->merge_rule_chain, entries) {
			if (!mrule->inherited &&
			    rule_dir_depth > mrule->depth)
				continue;

			ract = rule_iter_impl(mrule->ruleset, path,
			    filter, postcall, iter_fn, cookie);
			if (ract == RULE_ITER_HALT_CHAIN) {
				ract = RULE_ITER_CONTINUE;
				break;
			} else if (ract != RULE_ITER_CONTINUE) {
				/* Shouldn't be able to see SKIP here. */
				assert(ract == RULE_ITER_HALT);
				goto out;
			}
		}

		if (postcall) {
			ract = (*iter_fn)(ruleset, r, path, cookie);
			assert(ract != RULE_ITER_SKIP);
			if (ract == RULE_ITER_HALT_CHAIN) {
				haltchain = true;
				ract = RULE_ITER_CONTINUE;
			} else if (ract != RULE_ITER_CONTINUE) {
				assert(ract == RULE_ITER_HALT);
				break;
			}
		}
	}

	/* If we're not otherwise halting, bubble up the HALT_CHAIN. */

	if (ract == RULE_ITER_CONTINUE && haltchain)
		ract = RULE_ITER_HALT_CHAIN;
out:
	return ract;
}

/*
 * Runs rule_iter_impl() on the arguments, and returns true if the
 * filter ran to completion or false if it was halted.
 */
static bool
rule_iter(struct ruleset *ruleset, const char *path, enum rule_type filter,
    bool postcall, rule_iter_fn *iter_fn, void *cookie)
{
	enum rule_iter_action ret;

	ret = rule_iter_impl(ruleset, path, filter, postcall, iter_fn,
	    cookie);

	/*
	 * The implementation returns a rule_iter_action in case it's
	 * nested, we may need to propagate up a HALT_CHAIN or some
	 * such.  We'll just convert it at the boundary here -- we
	 * shouldn't ever observe a SKIP here, because that's internal
	 * to the iterator.
	 */

	assert(ret != RULE_ITER_SKIP);
	if (ret != RULE_ITER_CONTINUE && ret != RULE_ITER_HALT_CHAIN)
		return false;
	return true;
}

/*
 * FIXME: THIS WILL EXIT ON FAILURE.
 */
static enum rule_iter_action
rule_dir_push(struct ruleset *parent, struct rule *r, const char *path,
    void *cookie)
{
	char			 mfile[PATH_MAX];
	struct stat		 st;
	struct merge_rule	*mrule;
	struct rule_dir_ctx	 ctx = *(struct rule_dir_ctx *)cookie;
	size_t			 stripdir = ctx.stripdir;
	int			 delim = ctx.delim;

	/*
	 * This is just a bit of an optimization; if we had a clear rule
	 * appear after this in the parent chain, then we won't be
	 * evaluating these rules anyways so we can skip checking for
	 * them entirely.  Even if we didn't do this here,
	 * rule_match_evaluate() would still do the right thing and skip
	 * any chains we loaded.
	 */

	if (rule_cleared(parent, r))
		return RULE_ITER_SKIP;

	/* Not worried about truncation; stat() will fail. */
	(void)snprintf(mfile, sizeof(mfile), "%s/%s", path, r->pattern);

	if (stat(mfile, &st) == -1) {
		if (errno != ENOENT)
			err(ERR_FILEGEN, "stat");
		return RULE_ITER_CONTINUE;
	}

	/*
	 * We have a file, now we need to allocate and populate a new
	 * merge_rule.
	 */

	mrule = calloc(1, sizeof(*mrule));
	if (mrule == NULL)
		err(ERR_NOMEM, "calloc");

	mrule->ruleset = calloc(1, sizeof(*mrule->ruleset));
	if (mrule->ruleset == NULL)
		err(ERR_NOMEM, "calloc");

	mrule->path = strdup(path + stripdir);
	if (mrule->path == NULL)
		err(ERR_NOMEM, "strdup");

	mrule->ruleset->parent_set = parent;
	mrule->ruleset->lclear = (size_t)-1;
	mrule->parent_rule = r;
	mrule->inherited = (r->modifiers & MOD_MERGE_NO_INHERIT) == 0;
	mrule->depth = rule_dir_depth;

	TAILQ_INSERT_HEAD(&r->merge_rule_chain, mrule, entries);

	ruleset_do_merge(mrule->ruleset, mfile, r->modifiers & MOD_MERGE_MASK, delim);

	return RULE_ITER_CONTINUE;
}

/*
 * FIXME: THIS WILL CALL err() ON ERRORS.
 */
void
rules_dir_push(const char *path, size_t stripdir, int delim)
{
	struct rule_dir_ctx ctx;

	ctx.stripdir = stripdir;
	ctx.delim = delim;

	rule_dir_depth++;
	(void)rule_iter(&global_ruleset, path, RULE_DIR_MERGE, 0,
	    &rule_dir_push, &ctx);
}

static void
rule_dir_free(struct rule *r, struct merge_rule *mrule)
{

	TAILQ_REMOVE(&r->merge_rule_chain, mrule, entries);
	ruleset_free(mrule->ruleset);
	free(mrule->path);
	free(mrule);
}

static enum rule_iter_action
rule_dir_pop(struct ruleset *ruleset, struct rule *r, const char *path,
    void *cookie)
{
	struct merge_rule *mrule;

	mrule = TAILQ_FIRST(&r->merge_rule_chain);
	if (mrule == NULL)
		return RULE_ITER_CONTINUE;

	if (strcmp(mrule->path, path) == 0)
		rule_dir_free(r, mrule);

	/*
	 * If there's a rule earlier in the chain, then we messed up
	 * somewhere along the line.
	 */

	TAILQ_FOREACH(mrule, &r->merge_rule_chain, entries)
		assert(strcmp(mrule->path, path) != 0);

	return RULE_ITER_CONTINUE;
}

/*
 * Remove a directory from the global rule sets.
 */
void
rules_dir_pop(const char *path, size_t stripdir)
{
	(void)rule_iter(&global_ruleset, path + stripdir, RULE_DIR_MERGE, 1,
	    &rule_dir_pop, NULL);
	rule_dir_depth--;
}

/*
 * For a given path (and whether it's a directory), and whether we're a
 * sender or a receiver, and whether it's perishable (it's ignored in
 * directories that are being deleted), determine whether the path
 * matches any rules (i.e., the file is skipped).
 */
int
rules_match(const char *path, bool isdir, enum fmode rulectx,
    bool perishing)
{
	struct rule_match_ctx ctx;

	assert(rule_base != NULL);

	if (isdir && (strcmp(path, ".") == 0 || strcmp(path, "./") == 0))
		return 0;

	ctx.abspath[0] = '\0';
	ctx.isdir = isdir;
	ctx.match = 0;
	ctx.perishing = perishing;
	ctx.rulectx = rulectx;

	ctx.basename = strrchr(path, '/');
	if (ctx.basename != NULL)
		ctx.basename += 1;
	else
		ctx.basename = path;

	(void)rule_iter(&global_ruleset, path, RULE_NONE, false,
	    rule_match_evaluate, &ctx);
	return ctx.match;
}

