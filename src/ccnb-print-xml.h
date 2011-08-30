/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#ifndef _CCNB_DECODER_H_
#define _CCNB_DECODER_H_

#include "ns3/ns3-compat.h"
#include "ns3/ccnb-parser-void-visitor.h"

using namespace ns3;

extern "C"
{
#include <ccn/coding.h>
} // extern "C"

/* formatting_flags */
#define FORCE_BINARY   (1 << 0)
#define PREFER_HEX     (1 << 1)
#define VERBOSE_DECODE (1 << 2)

#define CCN_NO_SCHEMA INT_MIN
#define CCN_UNKNOWN_SCHEMA (INT_MIN+1)

class CcnbXmlPrinter : public CcnbParser::VoidVisitor
{
public:
  CcnbXmlPrinter (int formatting_flags, const ccn_dict *dtags);
  ~CcnbXmlPrinter ();

  size_t
  DecodeAndPrint (const char *p, size_t n);

public:
  virtual void visit (CcnbParser::Blob& n, boost::any param);
  virtual void visit (CcnbParser::Udata&n, boost::any param);
  virtual void visit (CcnbParser::Attr& n, boost::any param);
  virtual void visit (CcnbParser::Tag&  n, boost::any param);
  virtual void visit (CcnbParser::Dtag& n, boost::any param);
  virtual void visit (CcnbParser::Dattr&n, boost::any param);
  virtual void visit (CcnbParser::Ext&  n, boost::any param);

private:
  void ProcessTag (CcnbParser::BaseTag &n, boost::any param);
  
private:
  const ccn_dict_entry *m_tagdict;
  int m_tagdict_count;
  int m_formatting_flags;
};

class DecoderException {};

#endif // _CCNB_DECODER_H_
