/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#ifndef _NDNB_DECODER_H_
#define _NDNB_DECODER_H_

#include "dtag-dict.h"
#include "ns3/ns3-compat.h"
#include "ns3/ndnb-parser-void-visitor.h"

using namespace ns3;

/* formatting_flags */
#define FORCE_BINARY   (1 << 0)
#define PREFER_HEX     (1 << 1)
#define VERBOSE_DECODE (1 << 2)

#define NDN_NO_SCHEMA INT_MIN
#define NDN_UNKNOWN_SCHEMA (INT_MIN+1)

class NdnbXmlPrinter : public NdnbParser::VoidVisitor
{
public:
  NdnbXmlPrinter (int formatting_flags, const ndn_dict *dtags);
  ~NdnbXmlPrinter ();

  size_t
  DecodeAndPrint (const char *p, size_t n);

public:
  virtual void visit (NdnbParser::Blob& n, boost::any param);
  virtual void visit (NdnbParser::Udata&n, boost::any param);
  virtual void visit (NdnbParser::Attr& n, boost::any param);
  virtual void visit (NdnbParser::Tag&  n, boost::any param);
  virtual void visit (NdnbParser::Dtag& n, boost::any param);
  virtual void visit (NdnbParser::Dattr&n, boost::any param);
  virtual void visit (NdnbParser::Ext&  n, boost::any param);

private:
  void ProcessTag (NdnbParser::BaseTag &n, boost::any param);
  
private:
  const ndn_dict_entry *m_tagdict;
  int m_tagdict_count;
  int m_formatting_flags;
};

class DecoderException {};

#endif // _NDNB_DECODER_H_
