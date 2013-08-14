/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#ifndef _NDNB_PLAIN_PRINTER_H_
#define _NDNB_PLAIN_PRINTER_H_

#include "ns3/ns3-compat.h"
#include "ns3/ndnb-parser-void-visitor.h"

using namespace ns3;

class NdnbPlainPrinter : public NdnbParser::VoidVisitor
{
public:
  NdnbPlainPrinter ();
  ~NdnbPlainPrinter ();

  void
  SetOptions (bool verbose, bool signature, bool minimal)
  {
    m_verbose = verbose;
    m_signature = signature;
    m_minimal = minimal;
  }

public:
  virtual void visit (NdnbParser::Blob& n, boost::any) {}
  virtual void visit (NdnbParser::Udata&n, boost::any) {}
  virtual void visit (NdnbParser::Tag&,    boost::any) {}
  virtual void visit (NdnbParser::Dtag&,   boost::any);
  virtual void visit (NdnbParser::Attr& n, boost::any) {}
  virtual void visit (NdnbParser::Dattr&,  boost::any) {}
  virtual void visit (NdnbParser::Ext&  n, boost::any) {}

private:
  void ProcessTag (NdnbParser::BaseTag &n, boost::any param);

private:
  bool m_verbose;
  bool m_signature;
  bool m_minimal;
};

class PlainDecoderException {};

#endif // _NDNB_PLAIN_PRINTER_H_
