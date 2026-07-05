/*
 * This file is in the public domain.
 */
#include "../../config.h"

#include <errno.h>
#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "regress.h"

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

/* ---- output capture helper ---- */

/*
 * Redirects fd (STDERR_FILENO or STDOUT_FILENO) to a pipe for the
 * duration of one log_format_type() call, restores it, and returns the
 * single captured line via getline(). The write-side fd is fully closed
 * before reading (both our dup and the one installed at `fd`) so a
 * silent call can't hang getline() waiting on EOF.
 *
 * Caller must free() the returned string. NULL on harness setup failure
 * or an empty/EOF capture. Pipe capacity is bounded (PIPE_BUF+), unlike
 * open_memstream(); fine for one line, not for arbitrarily large output.
 */
static char *
capture_log_format_type(const struct sess *sess, enum log_type type,
    const char *format, const struct flist *fl, int fd, bool *ok_out)
{
        int     pipefd[2];
        FILE   *read_end;
        FILE   *stream;
        int     saved_fd;
        bool    ok;
        char   *line = NULL;
        size_t  linecap = 0;
        ssize_t linelen;

        stream = (fd == STDOUT_FILENO) ? stdout : stderr;

        if (pipe(pipefd) != 0)
                return NULL;

        read_end = fdopen(pipefd[0], "r");
        if (read_end == NULL) {
                close(pipefd[0]);
                close(pipefd[1]);
                return NULL;
        }

        saved_fd = dup(fd);
        if (saved_fd == -1) {
                fclose(read_end); /* also closes pipefd[0] */
                close(pipefd[1]);
                return NULL;
        }

        fflush(stream);
        if (dup2(pipefd[1], fd) == -1) {
                close(saved_fd);
                fclose(read_end);
                close(pipefd[1]);
                return NULL;
        }
        close(pipefd[1]); /* fd now holds an equivalent reference */

        ok = log_format_type(type, sess, format, fl);

        fflush(stream);

        /* Restore; closes the pipe dup installed at fd. */
        dup2(saved_fd, fd);
        close(saved_fd);

        linelen = getline(&line, &linecap, read_end);
        if (linelen < 0) {
                free(line);
                line = NULL;
        }

        fclose(read_end);

        if (ok_out != NULL)
                *ok_out = ok;

        return line;
}

/* ---- Test fixtures ---- */

static struct opts  g_opts;
static struct sess  g_sess;
static struct flist g_fl;

static int
suite_init(void)
{
        /* Pin TZ so %M's expected localtime() string is deterministic. */
        setenv("TZ", "UTC", 1);
        tzset();

        memset(&g_opts, 0, sizeof(g_opts));
        memset(&g_sess, 0, sizeof(g_sess));
        memset(&g_fl, 0, sizeof(g_fl));

        g_sess.opts = &g_opts;

        g_fl.path = "some/relative/path/file.txt";
        g_fl.wpath = "file.txt";
        g_fl.link = NULL;
        g_fl.iflags = 0;

        g_fl.st.mode = 0100644; /* regular file, -rw-r--r-- */
        g_fl.st.uid = 1000;
        g_fl.st.gid = 1000;
        g_fl.st.size = 4096;
        g_fl.st.mtime = 1750000000; /* arbitrary fixed epoch time */

        return 0;
}

static int
suite_clean(void)
{
        return 0;
}

/* ---- Tests ---- */

/*
 * No '%' escapes: emitted verbatim.
 */
static void
test_literal_string_no_escapes(void)
{
        char *line;
        bool  ok;

        line = capture_log_format_type(&g_sess, LT_WARNING, "hello world",
            &g_fl, STDERR_FILENO, &ok);
        CU_ASSERT_PTR_NOT_NULL_FATAL(line);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_STRING_EQUAL(line, "hello world\n");

        free(line);
}

/*
 * %f -> flist->path (long form); %n -> flist->wpath (short form).
 */
static void
test_percent_f_and_n_expand_to_path_and_wpath(void)
{
        char *line;
        bool  ok;

        line = capture_log_format_type(&g_sess, LT_WARNING, "%f %n", &g_fl,
            STDERR_FILENO, &ok);
        CU_ASSERT_PTR_NOT_NULL_FATAL(line);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_STRING_EQUAL(line,
            "some/relative/path/file.txt file.txt\n");

        free(line);
}

/*
 * Field-width syntax, doc's own example: "%-50n %8l %07p". %-50n
 * left-justifies wpath in 50; %8l right-justifies size in 8; %07p
 * zero-pads pid in 7. %p has no backing field/known value, so the
 * expected string is built from getpid() at runtime rather than
 * hardcoded.
 */
static void
test_field_width_syntax(void)
{
        char  expected[256];
        char *line;
        bool  ok;

        snprintf(expected, sizeof(expected), "%-50s %8lld %07lld\n",
            g_fl.wpath, (long long)g_fl.st.size, (long long)getpid());

        line = capture_log_format_type(&g_sess, LT_WARNING,
            "%-50n %8l %07p", &g_fl, STDERR_FILENO, &ok);
        CU_ASSERT_PTR_NOT_NULL_FATAL(line);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_STRING_EQUAL(line, expected);

        free(line);
}

/*
 * Human-readable levels (per rsync's --human-readable, since the given
 * doc excerpt doesn't itself spell out the per-level format):
 *   1 apostrophe  -> comma-grouped digits, no unit suffix
 *   2 apostrophes -> units of 1000, K/M/G/T/P suffix
 *   3 apostrophes -> units of 1024, same suffixes
 * Each test overrides st.size to a value chosen to avoid rounding
 * ambiguity, then restores it.
 */

/*
 * %'l: comma-grouped digits.
 */
static void
test_human_readable_level1(void)
{
        off_t saved_size = g_fl.st.size;
        char *line;
        bool  ok;

        g_fl.st.size = 1234567;

        line = capture_log_format_type(&g_sess, LT_WARNING, "%'l", &g_fl,
            STDERR_FILENO, &ok);
        CU_ASSERT_PTR_NOT_NULL_FATAL(line);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_TRUE(strcmp(line, "1234567\n") == 0 ||
            strcmp(line, "1,234,567\n") == 0);

        g_fl.st.size = saved_size;
        free(line);
}

/*
 * %''l: units of 1000; value/expected are the manpage's own example.
 */
static void
test_human_readable_level2(void)
{
        off_t saved_size = g_fl.st.size;
        char *line;
        bool  ok;

        g_fl.st.size = 1234567;

        line = capture_log_format_type(&g_sess, LT_WARNING, "%''l", &g_fl,
            STDERR_FILENO, &ok);
        CU_ASSERT_PTR_NOT_NULL_FATAL(line);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_STRING_EQUAL(line, "1.2M\n");

        g_fl.st.size = saved_size;
        free(line);
}

/*
 * %'''l: units of 1024; exact power of 1024 sidesteps rounding ambiguity.
 */
static void
test_human_readable_level3(void)
{
        off_t saved_size = g_fl.st.size;
        char *line;
        bool  ok;

        g_fl.st.size = 1048576; /* 1 MiB exactly */

        line = capture_log_format_type(&g_sess, LT_WARNING, "%'''l", &g_fl,
            STDERR_FILENO, &ok);
        CU_ASSERT_PTR_NOT_NULL_FATAL(line);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_STRING_EQUAL(line, "1.0M\n");

        g_fl.st.size = saved_size;
        free(line);
}

/*
 * %B mode -> "-rw-r--r--"
 * %U/%G   -> plain decimal ("1000"/"1000"; gid isn't the DEFAULT sentinel)
 * %l      -> plain decimal size ("4096")
 * %M      -> "%Y/%m/%d-%H:%M:%S" localtime, UTC-pinned
 */
static void
test_all_flstat_escapes(void)
{
        char *line;
        bool  ok;

        line = capture_log_format_type(&g_sess, LT_WARNING,
            "%B %U %G %l %M", &g_fl, STDERR_FILENO, &ok);
        CU_ASSERT_PTR_NOT_NULL_FATAL(line);
        CU_ASSERT_TRUE(ok);

        CU_ASSERT_STRING_EQUAL(line,
            "-rw-r--r-- 1000 1000 4096 2025/06/15-15:06:40\n");

        free(line);
}

/* ---- Suite registration ---- */

struct test_case {
        const char  *name;
        CU_TestFunc  func;
};

static const struct test_case common_tests[] = {
        { "literal_string_no_escapes",             test_literal_string_no_escapes },
        { "percent_f_and_n_expand_to_path_and_wpath",
            test_percent_f_and_n_expand_to_path_and_wpath },
        { "field_width_syntax",                     test_field_width_syntax },
        { "human_readable_level1",                  test_human_readable_level1 },
        { "human_readable_level2",                  test_human_readable_level2 },
        { "human_readable_level3",                  test_human_readable_level3 },
        { "all_flstat_escapes",                     test_all_flstat_escapes },
};

int
main(void)
{
        CU_pSuite suite;
        size_t    i;

	setlocale(LC_NUMERIC, "");

        if (CU_initialize_registry() != CUE_SUCCESS)
                return CU_get_error();

        suite = CU_add_suite("log_format_type", suite_init, suite_clean);
        if (suite == NULL) {
                CU_cleanup_registry();
                return CU_get_error();
        }

        for (i = 0; i < sizeof(common_tests) / sizeof(common_tests[0]); i++) {
                if (CU_add_test(suite, common_tests[i].name,
                    common_tests[i].func) == NULL) {
                        CU_cleanup_registry();
                        return CU_get_error();
                }
        }

        CU_basic_set_mode(CU_BRM_VERBOSE);

        rsync_set_logfile(stdout, NULL);

        CU_basic_run_tests();

        int failures = CU_get_number_of_failures();
        CU_cleanup_registry();
        return failures != 0;
}
