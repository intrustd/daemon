#include <stdio.h>
#include <check.h>

#include "../token.h"

static const char token_data[] = "{\"permissions\": [\"kite+perm://flywithkite.com/admin/site\", \"kite+perm://flywithkite.com/photos/upload\", \"kite+perm://flywithkite.com/photos/gallery\", \"kite+perm://flywithkite.com/photos/comment\"], \"applications\": [\"kite+app://flywithkite.com/admin\", \"kite+app://flywithkite.com/photos\"], \"login_required\": false, \"site\": \"SHA256:1fe0a2b0fc1c8007f5b5e39f57a9acfe49c99acd93f26c69a59add91787eee09\", \"expiration\": \"2018-10-12T05:25:17.167371\"}";

START_TEST(test_read_token)
{
  struct token *tok;
  static const char new_file_tmpl[] = ".token.XXXXXX";
  char new_file[sizeof(new_file_tmpl)];
  FILE *fl;

  memcpy(new_file, new_file_tmpl, sizeof(new_file_tmpl));

  assert(mkstemp(new_file));
  fl = fopen(new_file, "wt");

  fprintf(fl, "%s", token_data);
  fclose(fl);

  tok = token_new_from_path(new_file);
  ck_assert(tok);
  TOKEN_UNREF(tok);
}
END_TEST

Suite *token_suite() {
  Suite *s;
  TCase *tc;

  s = suite_create("Tokens");

  tc = tcase_create("Read token");
  tcase_add_test(tc, test_read_token);

  suite_add_tcase(s, tc);

  return s;
}
