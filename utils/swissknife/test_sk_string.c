/*
 * test_sk_string.c
 */

#ifdef NDEBUG
#undef NDEBUG
#endif /* NDEBUG */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <sk_common.h>
#include <sk_string.h>
#include <tmdebug.h>

#define STR_1 "Hello"
#define STR_2 ","
#define STR_3 " "
#define STR_4 "world"
#define STR_5 "!"
#define STR_0 STR_1 STR_2 STR_3 STR_4 STR_5

static void assert_size(const sk_string_t *string, int expected)
{
    int actual = -1;

    assert(string != NULL);
    assert(expected >= 0);

    assert(sk_string_get_size(string, &actual) == 0);
    assert(actual == expected);
}

static void assert_content(const sk_string_t *string, const char *expected)
{
    char *actual = NULL;

    assert(string != NULL);
    assert(expected != NULL);

    assert_size(string, strlen(expected));
    assert(sk_string_get_string(string, &actual) == 0);
    assert(actual != NULL);
    assert(strcmp(actual, expected) == 0);
}

void test_reset(sk_string_t *string)
{
    assert(string != NULL);

    assert(sk_string_reset(string) == 0);
    assert_size(string, 0);
    assert_content(string, "");
}


void test_append_range(sk_string_t *string)
{
#define RANGE(str__) (str__), ((str__) + sizeof(str__) - 1)

    static const char str_0[] = STR_0;
    static const char str_1[] = STR_1;
    static const char str_2[] = STR_2;
    static const char str_3[] = STR_3;
    static const char str_4[] = STR_4;
    static const char str_5[] = STR_5;

    static const char str_null[] = "";
    static const char str_0_str_0[] = STR_0 STR_0;

    assert(string != NULL);

    test_reset(string);
    assert(sk_string_append_range(string, RANGE(str_1)) == 0);
    assert_content(string, STR_1);
    assert(sk_string_append_range(string, RANGE(str_2)) == 0);
    assert_content(string, STR_1 STR_2);
    assert(sk_string_append_range(string, RANGE(str_3)) == 0);
    assert_content(string, STR_1 STR_2 STR_3);
    assert(sk_string_append_range(string, RANGE(str_4)) == 0);
    assert_content(string, STR_1 STR_2 STR_3 STR_4);
    assert(sk_string_append_range(string, RANGE(str_5)) == 0);
    assert_content(string, STR_0);
    assert(sk_string_append_range(string, RANGE(str_null)) == 0);
    assert_content(string, STR_0);
    assert(sk_string_append_range(string, RANGE(str_0)) == ENOSPC);
    assert_content(string, STR_0);
    assert(sk_string_reset(string) == 0);
    assert_content(string, "");
    assert(sk_string_append_range(string, RANGE(str_0_str_0)) == ENOSPC);
    assert_content(string, STR_0);
}

void test_append_string(sk_string_t *string)
{
    assert(string != NULL);

    test_reset(string);
    assert(sk_string_append_string(string, STR_1) == 0);
    assert_content(string, STR_1);
    assert(sk_string_append_string(string, STR_2) == 0);
    assert_content(string, STR_1 STR_2);
    assert(sk_string_append_string(string, STR_3) == 0);
    assert_content(string, STR_1 STR_2 STR_3);
    assert(sk_string_append_string(string, STR_4) == 0);
    assert_content(string, STR_1 STR_2 STR_3 STR_4);
    assert(sk_string_append_string(string, STR_5) == 0);
    assert_content(string, STR_0);
    assert(sk_string_append_string(string, "") == 0);
    assert_content(string, STR_0);
    assert(sk_string_append_string(string, STR_0) == ENOSPC);
    assert_content(string, STR_0);
    assert(sk_string_reset(string) == 0);
    assert_content(string, "");
    assert(sk_string_append_string(string, STR_0 STR_0) == ENOSPC);
    assert_content(string, STR_0);
}

void test_append_printf(sk_string_t *string)
{
    assert(string != NULL);

    test_reset(string);
    assert(sk_string_append_printf(string, "%d + %d = %s", 1, 2, "3") == 0);
    assert_content(string, "1 + 2 = 3");

    test_reset(string);
    assert(sk_string_append_printf(string, "%s" STR_2 STR_3 "%s" STR_5, STR_1, STR_4) == 0);
    assert_content(string, STR_0);

    test_reset(string);
    assert(sk_string_append_printf(string, "%s%s", STR_0, STR_0) == ENOSPC);
    assert_content(string, STR_0);
}

void test_append_format_1(void)
{
    char buffer_[1024];
    sk_string_t string;

    assert(sk_string_create(&string, buffer_, sizeof(buffer_)) == 0);
    assert(sk_string_append_format(&string, "$0 + $1 = $1 + $0", "var1", "var2") == 0);
    assert_content(&string, "var1 + var2 = var2 + var1");
    test_reset(&string);
    assert(sk_string_append_format(&string,
                                   "$0 + $3 = $4 + $0",
                                   "var0", "var1", "var2", "var3", "var4") == 0);
    assert_content(&string, "var0 + var3 = var4 + var0");
    test_reset(&string);
    assert(sk_string_append_format(&string,
                                   "\"$0$1$2\" x 3 = \"$0$1$2$0$1$2$0$1$2\"",
                                   "a", "b", "c") == 0);
    assert_content(&string, "\"abc\" x 3 = \"abcabcabc\"");
    test_reset(&string);
    assert(sk_string_append_format(&string, "$$$0 = $$$0 * $$$1 * $$$2;", "i", "j", "k") == 0);
    assert_content(&string, "$i = $i * $j * $k;");
    assert(sk_string_destroy(&string) == 0);
}

void test_append_format_2(void)
{
    char buffer_[sizeof("01234") + SK_STRING_DIFF];
    sk_string_t string;

    assert(sk_string_create(&string, buffer_, sizeof(buffer_)) == 0);
    assert(sk_string_append_format(&string,
                                   "$0$1$2$3$4$5$6$7$8$9",
                                   "0", "1", "2", "3", "4", "5", "6", "7", "8", "9") == ENOSPC);
    assert_content(&string, "01234");
    assert(sk_string_destroy(&string) == 0);
}

void test_append_format_3(void)
{
    char buffer_[128 + SK_STRING_DIFF];
    sk_string_t string;

    assert(sk_string_create(&string, buffer_, sizeof(buffer_)) == 0);
    assert(sk_string_append_format(&string, "It is $N.") == 0);
    puts(sk_string_get_content(&string));
    assert(sk_string_destroy(&string) == 0);
}

void test_urlenc(void)
{
    char buffer_[128 + SK_STRING_DIFF];
    sk_string_t string;

    assert(sk_string_create(&string, buffer_, sizeof(buffer_)) == 0);
    assert(sk_string_append_string_urlenc(&string, "pi=3&e=2&s=\"Hello, world!\n\"") == 0);
    puts(sk_string_get_content(&string));
    assert(sk_string_destroy(&string) == 0);
}

void test(void)
{
    char buffer_[sizeof(STR_0) + SK_STRING_DIFF];
    sk_string_t string;

    assert(sk_string_create(&string, buffer_, sizeof(buffer_)) == 0);
    assert_content(&string, "");
    test_append_range(&string);
    test_append_string(&string);
    test_append_printf(&string);
    assert(sk_string_destroy(&string) == 0);
    test_append_format_1();
    test_append_format_2();
    test_append_format_3();
    test_urlenc();

    SK_LOG_INFO("All test cases passed");
}

int main(void)
{
    assert(tmDebugOpenDefault(TmDebugConsole, NULL) == 0);
    test();
    assert(tmDebugCloseDefault() == 0);
    return 0;
}
