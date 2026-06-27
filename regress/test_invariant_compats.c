#include <check.h>
#include <stdlib.h>
#include <limits.h>

/* Forward declaration of the function from compats.c */
extern void *alloc_buffer(size_t count, size_t size);

START_TEST(test_overflow_protection)
{
    /* Invariant: Multiplication for allocation size must not overflow */
    struct {
        size_t count;
        size_t size;
        const char *description;
    } test_cases[] = {
        {SIZE_MAX, 2, "Exploit case: multiplication wraps to small value"},
        {SIZE_MAX / 2 + 1, 2, "Boundary case: just overflows"},
        {100, 10, "Valid case: no overflow"},
        {0, SIZE_MAX, "Zero count with max size"},
        {SIZE_MAX, 0, "Max count with zero size"}
    };
    
    for (int i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        void *result = alloc_buffer(test_cases[i].count, test_cases[i].size);
        
        /* Security property: Either allocation succeeds with correct size,
           or overflow is detected and function returns NULL/fails safely */
        if (test_cases[i].count != 0 && test_cases[i].size != 0) {
            if (test_cases[i].count > SIZE_MAX / test_cases[i].size) {
                /* Overflow expected - function should handle safely */
                ck_assert_msg(result == NULL || 
                             (result != NULL && 
                              /* If it allocates, verify it's not dangerously small */
                              malloc_usable_size(result) >= test_cases[i].count * test_cases[i].size),
                             "Failed to handle overflow for case: %s", 
                             test_cases[i].description);
            } else {
                /* No overflow - allocation should succeed */
                ck_assert_msg(result != NULL, 
                             "Valid allocation failed for case: %s", 
                             test_cases[i].description);
                free(result);
            }
        } else {
            /* Zero-sized allocation cases */
            if (result != NULL) {
                free(result);
            }
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_overflow_protection);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}