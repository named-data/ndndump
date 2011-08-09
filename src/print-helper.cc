/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#include "print-helper.h"

#include <stdio.h>

extern "C"
{
#include <ccn/coding.h>
}
  
const char Base64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const char *
PrintHelper::dict_name_from_number (int ndx, const struct ccn_dict_entry *dict, int n)
{
  int i;
  for (i = 0; i < n; i++)
    if (ndx == dict[i].index)
      return (dict[i].name);
  return (NULL);
}

const char PrintHelper::Base64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int
PrintHelper::is_text_encodable(const unsigned char *p, size_t start, size_t length)
{
  size_t i;

  if (length == 0) return (0);
  for (i = 0; i < length; i++)
    {
      char c = p[start + i];
      if (c < ' ' || c > '~') return (0);
      if (c == '<' || c == '>' || c == '&') return (0);
    }
  return (1);
}

/* see ccn_uri_append_percentescaped */
void
PrintHelper::print_percent_escaped(const unsigned char *data, size_t size)
{
  size_t i;
  unsigned char ch;
  for (i = 0; i < size && data[i] == '.'; i++)
    continue;
  /* For a component that consists solely of zero or more dots, add 3 more */
  if (i == size)
    printf("...");
  for (i = 0; i < size; i++)
    {
      ch = data[i];
      /*
       * Leave unescaped only the generic URI unreserved characters.
       * See RFC 3986. Here we assume the compiler uses ASCII.
       */
      if (('a' <= ch && ch <= 'z') ||
          ('A' <= ch && ch <= 'Z') ||
          ('0' <= ch && ch <= '9') ||
          ch == '-' || ch == '.' || ch == '_' || ch == '~')
        printf("%c", ch);
      else
        printf("%%%02X", (unsigned)ch);
    }
}

