/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#ifndef _CCNB_DECODER_H_
#define _CCNB_DECODER_H_

#include <stdint.h>
#include <limits.h>

extern "C"
{
#include <ccn/charbuf.h>
}
  
/* formatting_flags */
#define FORCE_BINARY   (1 << 0)
#define PREFER_HEX     (1 << 1)
#define VERBOSE_DECODE (1 << 2)

#define CCN_NO_SCHEMA INT_MIN
#define CCN_UNKNOWN_SCHEMA (INT_MIN+1)

struct ccn_decoder_stack_item {
  size_t nameindex; /* byte index into stringstack */
  size_t savedss;
  int saved_schema;
  int saved_schema_state;
  struct ccn_decoder_stack_item *link;
};

enum callback_kind {
  CALLBACK_INITIAL,
  CALLBACK_OBJECTEND,
  CALLBACK_FINAL
};

class CcnbDecoder;
typedef void (*ccn_decoder_callback)(
                                     struct CcnbDecoder *d,
                                     enum callback_kind kind,
                                     void *data
                                     );

class CcnbDecoder
{
public:
  CcnbDecoder (int formatting_flags, const struct ccn_dict *dtags);
  ~CcnbDecoder ();

  size_t
  DecodeAndPrint (const unsigned char *p, size_t n);

  void
  SetCallback (ccn_decoder_callback c, void *data);

private:
  struct ccn_decoder_stack_item *
  ccn_decoder_push ();

  void
  ccn_decoder_pop ();
  
private:
  int m_state;
  int m_tagstate;
  int m_bits;
  size_t m_numval;
  uintmax_t m_bignumval;
  int m_schema;
  int m_sstate;
  struct ccn_decoder_stack_item *m_stack;
  struct ccn_charbuf *m_stringstack;
  const struct ccn_dict_entry *m_tagdict;
  int m_tagdict_count;
  ccn_decoder_callback m_callback;
  void *m_callbackdata;
  int m_formatting_flags;
  int m_base64_char_count;
  struct ccn_charbuf *m_annotation;
};

class DecoderException {};

#endif // _CCNB_DECODER_H_
