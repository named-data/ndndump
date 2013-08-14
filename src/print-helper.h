/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#ifndef _PRINT_HELPER_H_
#define _PRINT_HELPER_H_

#include <stddef.h>
#include <iostream>

struct ndn_dict_entry;
extern struct ndn_dict ndn_dtag_dict2;

class PrintHelper
{
public:
  static const char *
  dict_name_from_number (int ndx, const struct ndn_dict_entry *dict, int n);
  
  static int
  is_text_encodable (const unsigned char *p, size_t start, size_t length);
  
  /* see ndn_uri_append_percentescaped */
  static void
  print_percent_escaped (std::ostream &os, const unsigned char *data, size_t size);

  static void
  print_hex_ascii_line (std::ostream &os, const unsigned char *payload, int len, int offset);

  static void
  print_payload (std::ostream &os, const unsigned char *payload, int len);

  static const char Base64[];
};

class UnknownDtag {};

#endif // _PRINT_HELPER_H_

