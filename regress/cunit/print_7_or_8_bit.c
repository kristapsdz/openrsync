/*
 * This file is in the public domain.
 */
#include "../../config.h"

#include <sys/types.h>

#if HAVE_SBUF
# if __APPLE__
#  include <usbuf.h>
# else
#  include <sys/sbuf.h>
# endif
#else
# include "../../compat_sbuf.h"
#endif

#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "regress.h"

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

/* ---- Test fixtures ---- */

static struct opts g_opts;
static struct sess g_sess;

/*
 * Preferred UTF-8 locale name(s) to try, in order. "C.UTF-8" is glibc's
 * locale-independent UTF-8 locale and tends to be present even on minimal
 * systems; "en_US.UTF-8" is a common fallback on systems where it isn't.
 * If neither is installed, the UTF-8-locale suite's init fails and CUnit
 * reports that suite as errored -- install one of these locales
 * (e.g. `locale-gen en_US.UTF-8`) to run it.
 */
static const char *utf8_locale_candidates[] = {
        "C.UTF-8",
        "en_US.UTF-8",
        NULL,
};

/*
 * Common fixture: locale-independent tests. Locale is pinned to "C"
 * anyway, purely for determinism -- these tests don't rely on ctype
 * behavior that varies by locale (plain ASCII, control chars).
 */
static int
suite_init_common(void)
{
        if (setlocale(LC_ALL, "C") == NULL)
                return -1;
        g_opts.bit8 = false;
        g_sess.opts = &g_opts;
        return 0;
}

static int
suite_clean_common(void)
{
        return 0;
}

/*
 * "C" locale fixture: for the branch-3/4/5 tests, which depend on
 * isprint()'s classification of high (>=0x80) bytes.
 */
static int
suite_init_c_locale(void)
{
        if (setlocale(LC_ALL, "C") == NULL)
                return -1;
        g_opts.bit8 = false;
        g_sess.opts = &g_opts;
        return 0;
}

static int
suite_clean_c_locale(void)
{
        setlocale(LC_ALL, "C");
        return 0;
}

/*
 * UTF-8 locale fixture: re-runs the same branch-3/4/5 tests under a
 * UTF-8 locale, to confirm isprint()'s per-byte classification of
 * high bytes doesn't change just because the locale's charset does.
 */
static int
suite_init_utf8_locale(void)
{
        const char *got = NULL;

        for (int i = 0; utf8_locale_candidates[i] != NULL; i++) {
                got = setlocale(LC_ALL, utf8_locale_candidates[i]);
                if (got != NULL)
                        break;
        }
        if (got == NULL)
                return -1;

        g_opts.bit8 = false;
        g_sess.opts = &g_opts;
        return 0;
}

static int
suite_clean_utf8_locale(void)
{
        /* Reset to "C" so later suites aren't affected by this one. */
        setlocale(LC_ALL, "C");
        return 0;
}

/* ---- Tests ---- */

/*
 * ASCII-only input, no control chars, no backslash/#DDD collision, no
 * high-bit bytes: every character should be a straight passthrough into
 * the destination sbuf, formatted via "%s".
 */
static void
test_ascii_only_passthrough(void)
{
        struct sbuf *out;
        const char  *input = "Hello, World! 123 - rsync test.";
        bool         ok;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), input);

        sbuf_delete(out);
}

/*
 * Numeric-only input, no control chars, no backslash/#DDD collision, no
 * high-bit bytes: digits are printable ASCII, so every character should
 * be a straight passthrough into the destination sbuf, formatted via "%s".
 */
static void
test_numeric_only_passthrough(void)
{
        struct sbuf *out;
        const char  *input = "0123456789";
        bool         ok;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), input);

        sbuf_delete(out);
}

/*
 * Corner case: empty string input. The for-loop body never executes
 * (the first dereference of *p is the NUL terminator), so innerbuf stays
 * empty and the destination sbuf should end up containing "" via "%s".
 */
static void
test_empty_string_passthrough(void)
{
        struct sbuf *out;
        const char  *input = "";
        bool         ok;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), "");

        sbuf_delete(out);
}

/*
 * Top-level branch 1, via the c == '\t' disjunct specifically:
 * isprint('\t') is false, so without this explicit disjunct a tab would
 * fall through to branch 2 (control-char escape) instead of passing
 * through unchanged. This is a literal '\0' comparison, not a ctype
 * call, so it isn't locale-sensitive.
 */
static void
test_tab_character_passthrough(void)
{
        struct sbuf *out;
        const char  *input = "a\tb";
        bool         ok;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), input);

        sbuf_delete(out);
}

/*
 * Top-level branch 1, via the c == 0x7f disjunct specifically:
 * isprint(0x7f) (DEL) is false, so without this explicit disjunct DEL
 * would fall through to branch 5 (fallback escape) instead of passing
 * through unchanged. Like the tab case, this is a literal comparison,
 * not locale-sensitive.
 */
static void
test_del_character_passthrough(void)
{
        struct sbuf *out;
        const char  *input = "a\177b";
        bool         ok;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), input);

        sbuf_delete(out);
}

/*
 * Top-level branch 2: c < ' ' (control characters, excluding '\t' which
 * is caught earlier by branch 1). Each control byte should be escaped as
 * "\#NNN" zero-padded octal, regardless of bit8.
 */
static void
test_control_chars_escaped(void)
{
        struct sbuf *out;
        const char  *input    = "\001\002";
        const char  *expected = "\\#001\\#002";
        bool         ok;

        g_opts.bit8 = false;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), expected);

        sbuf_delete(out);
}

/*
 * ---- Nested branch: backslash/#DDD collision guard (inside branch 1) ----
 *
 * Within the printable/tab/DEL branch, there's a nested guard: a literal
 * backslash immediately followed by '#' and three digits gets the
 * backslash itself escaped (to avoid the output being ambiguous with the
 * function's own "\#NNN" escape syntax). All bytes involved here are
 * plain printable ASCII, so unlike the UTF-8/high-byte tests these are
 * not locale-sensitive.
 */

/*
 * Nested guard TRUE: backslash followed by '#' and exactly 3 digits.
 * The backslash (0x5c, decimal 92) is escaped as "\#134" -- 92 in
 * 3-digit octal is 134. The "#123abc" that follows is NOT consumed by
 * the lookahead -- it's printed verbatim on subsequent loop iterations,
 * since '#' and digits are themselves printable characters.
 */
static void
test_backslash_hash_ddd_collision_escaped(void)
{
        struct sbuf *out;
        const char  *input    = "\\#123abc";
        const char  *expected = "\\#134#123abc";
        bool         ok;

        g_opts.bit8 = false;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), expected);

        sbuf_delete(out);
}

/*
 * Nested guard FALSE: backslash followed by '#' but only 2 digits (the
 * 3rd isdigit() check reads the string's own NUL terminator, which
 * safely fails the check without reading out of bounds). The backslash
 * and everything after it should pass through unchanged.
 */
static void
test_backslash_no_collision_passthrough(void)
{
        struct sbuf *out;
        const char  *input = "\\#12";
        bool         ok;

        g_opts.bit8 = false;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), input);

        sbuf_delete(out);
}

/*
 * Nested guard FALSE, boundary case: backslash is the very last byte of
 * the string, so *(p+1) reads the NUL terminator itself (safe, still
 * within the string's allocated bytes) rather than '#'. The guard must
 * not trigger, and there must be no out-of-bounds read.
 */
static void
test_backslash_at_end_of_string_passthrough(void)
{
        struct sbuf *out;
        const char  *input = "abc\\";
        bool         ok;

        g_opts.bit8 = false;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), input);

        sbuf_delete(out);
}

/*
 * ---- Locale-sensitive tests ----
 *
 * The three tests below depend on isprint()'s classification of bytes
 * >= 0x80 (branches 3, 4, and 5 are only reachable for a given byte if
 * isprint() first returns false for it). That classification is, in
 * principle, locale-dependent, so each of these test functions is
 * registered under two suites -- one fixed to the "C" locale and one
 * fixed to a UTF-8 locale -- to confirm the function's escaping behavior
 * doesn't silently change depending on the process's locale.
 */

/*
 * Top-level branch 3: sess->opts->bit8 == true. A non-printable,
 * non-control, high byte should be passed through raw with no UTF-8
 * interpretation, even though it also happens to fall inside the
 * 0xc2-0xdf range checked by branch 4 -- branch 3 must take priority.
 */
static void
test_bit8_mode_passthrough(void)
{
        struct sbuf *out;
        const char  *input = "\225"; /* 0x95, non-printable in "C" locale */
        bool         ok;

        g_opts.bit8 = true;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), input);

        g_opts.bit8 = false;
        sbuf_delete(out);
}

/*
 * Top-level branch 3, mixed input: with bit8 == true, high bytes should
 * pass through raw regardless of whether they'd otherwise be a UTF-8
 * lead byte (0xc2-0xdf) or fall outside that range entirely -- branch 3
 * takes priority over branch 4 either way. At the same time, printable
 * ASCII and control characters earlier in the string should still be
 * handled by branches 1 and 2 exactly as if bit8 were false, since those
 * checks come before the bit8 check in the branch order.
 */
static void
test_bit8_mode_mixed_bytes_passthrough(void)
{
        struct sbuf *out;
        const char  *input    = "AB\001\200\303\377";
        const char  *expected = "AB\\#001\200\303\377";
        bool         ok;

        g_opts.bit8 = true;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), expected);

        g_opts.bit8 = false;
        sbuf_delete(out);
}

/*
 * Top-level branch 4: 0xc2 <= c <= 0xdf with bit8 == false, and a valid
 * continuation byte (0x80-0xdf) following it. Both bytes of the 2-byte
 * UTF-8 sequence should be passed through unchanged, and the loop should
 * correctly skip past the consumed continuation byte.
 *
 * 0xc3 0xa9 is the valid UTF-8 encoding of U+00E9 ("e" with acute accent).
 */
static void
test_utf8_two_byte_passthrough(void)
{
        struct sbuf *out;
        const char  *input = "\303\251";
        bool         ok;

        g_opts.bit8 = false;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), input);

        sbuf_delete(out);
}

/*
 * Nested guard FALSE (inside branch 4): lead byte in 0xc2-0xdf followed
 * by a byte that is NOT a valid continuation byte (0x80-0xdf). The lead
 * byte alone gets escaped as octal; the following byte is NOT consumed
 * by this branch and is processed independently on the next iteration.
 *
 * 0xc3 is a valid 2-byte UTF-8 lead byte, but 'A' (0x41) can't continue
 * it, so the sequence is not treated as UTF-8 here.
 */
static void
test_utf8_invalid_continuation_escaped(void)
{
        struct sbuf *out;
        const char  *input    = "\303A";
        const char  *expected = "\\#303A";
        bool         ok;

        g_opts.bit8 = false;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), expected);

        sbuf_delete(out);
}

/*
 * Nested guard FALSE, boundary case (inside branch 4): lead byte is the
 * very last byte of the string, so the continuation-byte check reads the
 * NUL terminator (0x00), which is outside 0x80-0xdf and safely fails the
 * guard without an out-of-bounds read. The lead byte alone is escaped.
 */
static void
test_utf8_lead_byte_at_end_of_string_escaped(void)
{
        struct sbuf *out;
        const char  *input    = "\302";
        const char  *expected = "\\#302";
        bool         ok;

        g_opts.bit8 = false;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), expected);

        sbuf_delete(out);
}

/*
 * Top-level branch 5: fallback else. A high byte outside the 0xc2-0xdf
 * lead-byte range, with bit8 == false, should be escaped as "\#NNN"
 * octal, just like a control character.
 */
static void
test_high_byte_escaped_no_bit8(void)
{
        struct sbuf *out;
        const char  *input    = "\377"; /* 0xff */
        const char  *expected = "\\#377";
        bool         ok;

        g_opts.bit8 = false;

        out = sbuf_new_auto();
        CU_ASSERT_PTR_NOT_NULL_FATAL(out);

        ok = print_7_or_8_bit(&g_sess, "%s", input, out);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_EQUAL_FATAL(sbuf_finish(out), 0);
        CU_ASSERT_STRING_EQUAL(sbuf_data(out), expected);

        sbuf_delete(out);
}

/* ---- Suite registration ---- */

struct test_case {
        const char  *name;
        CU_TestFunc  func;
};

static const struct test_case common_tests[] = {
        { "ascii_only_passthrough",
	  test_ascii_only_passthrough },
        { "numeric_only_passthrough",
	  test_numeric_only_passthrough },
        { "empty_string_passthrough",
	  test_empty_string_passthrough },
        { "tab_character_passthrough",
	  test_tab_character_passthrough },
        { "del_character_passthrough",
	  test_del_character_passthrough },
        { "control_chars_escaped",
	  test_control_chars_escaped },
        { "backslash_hash_ddd_collision_escaped",
          test_backslash_hash_ddd_collision_escaped },
        { "backslash_no_collision_passthrough",
          test_backslash_no_collision_passthrough },
        { "backslash_at_end_of_string_passthrough",
          test_backslash_at_end_of_string_passthrough },
};

/*
 * Registered under both the "C" locale suite and the UTF-8 locale suite
 * (see suite_init_c_locale()/suite_init_utf8_locale()) -- these tests
 * depend on isprint()'s classification of bytes >= 0x80.
 */
static const struct test_case locale_sensitive_tests[] = {
        { "bit8_mode_passthrough",
	  test_bit8_mode_passthrough },
        { "bit8_mode_mixed_bytes_passthrough",
          test_bit8_mode_mixed_bytes_passthrough },
        { "utf8_two_byte_passthrough",
	  test_utf8_two_byte_passthrough },
        { "utf8_invalid_continuation_escaped",
          test_utf8_invalid_continuation_escaped },
        { "utf8_lead_byte_at_end_of_string_escaped",
          test_utf8_lead_byte_at_end_of_string_escaped },
        { "high_byte_escaped_no_bit8",
	  test_high_byte_escaped_no_bit8 },
};

int
main(void)
{
        CU_pSuite	common_suite,
			c_locale_suite,
			utf8_locale_suite;
        size_t		i;

        if (CU_initialize_registry() != CUE_SUCCESS)
                return CU_get_error();

        /* ---- Common suite: locale-independent tests ---- */

        common_suite = CU_add_suite("print_7_or_8_bit_common",
            suite_init_common, suite_clean_common);
        if (common_suite == NULL) {
                CU_cleanup_registry();
                return CU_get_error();
        }

        for (i = 0; i < sizeof(common_tests) / sizeof(common_tests[0]); i++) {
                if (CU_add_test(common_suite, common_tests[i].name,
                    common_tests[i].func) == NULL) {
                        CU_cleanup_registry();
                        return CU_get_error();
                }
        }

        /* ---- "C" locale suite: locale-sensitive tests ---- */

        c_locale_suite = CU_add_suite("print_7_or_8_bit_c_locale",
            suite_init_c_locale, suite_clean_c_locale);
        if (c_locale_suite == NULL) {
                CU_cleanup_registry();
                return CU_get_error();
        }

        for (i = 0; i < sizeof(locale_sensitive_tests) /
            sizeof(locale_sensitive_tests[0]); i++) {
                if (CU_add_test(c_locale_suite, locale_sensitive_tests[i].name,
                    locale_sensitive_tests[i].func) == NULL) {
                        CU_cleanup_registry();
                        return CU_get_error();
                }
        }

        /* ---- UTF-8 locale suite: same tests, different locale ---- */

        utf8_locale_suite = CU_add_suite("print_7_or_8_bit_utf8_locale",
            suite_init_utf8_locale, suite_clean_utf8_locale);
        if (utf8_locale_suite == NULL) {
                CU_cleanup_registry();
                return CU_get_error();
        }

        for (i = 0; i < sizeof(locale_sensitive_tests) /
            sizeof(locale_sensitive_tests[0]); i++) {
                if (CU_add_test(utf8_locale_suite, locale_sensitive_tests[i].name,
                    locale_sensitive_tests[i].func) == NULL) {
                        CU_cleanup_registry();
                        return CU_get_error();
                }
        }

        CU_basic_set_mode(CU_BRM_VERBOSE);
        CU_basic_run_tests();

        int failures = CU_get_number_of_failures();
        CU_cleanup_registry();
        return failures != 0;
}
