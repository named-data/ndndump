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
  Decode (const unsigned char *p, size_t n);

  void
  SetCallback (ccn_decoder_callback c, void *data);

private:
  struct ccn_decoder_stack_item *
  ccn_decoder_push ();

  void
  ccn_decoder_pop ();
  
private:
  int state;
  int tagstate;
  int bits;
  size_t numval;
  uintmax_t bignumval;
  int schema;
  int sstate;
  struct ccn_decoder_stack_item *stack;
  struct ccn_charbuf *stringstack;
  const struct ccn_dict_entry *tagdict;
  int tagdict_count;
  ccn_decoder_callback callback;
  void *callbackdata;
  int formatting_flags;
  int base64_char_count;
  struct ccn_charbuf *annotation;
};

class DecoderException {};

#endif // _CCNB_DECODER_H_
