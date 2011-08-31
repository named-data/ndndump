/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#ifndef _CCNB_PLAIN_PRINTER_H_
#define _CCNB_PLAIN_PRINTER_H_

#include "ns3/ns3-compat.h"
#include "ns3/ccnb-parser-void-visitor.h"

using namespace ns3;

class CcnbPlainPrinter : public CcnbParser::VoidVisitor
{
public:
  CcnbPlainPrinter ();
  ~CcnbPlainPrinter ();

  void
  SetOptions (bool verbose, bool signature, bool minimal)
  {
    m_verbose = verbose;
    m_signature = signature;
    m_minimal = minimal;
  }

public:
  virtual void visit (CcnbParser::Blob& n, boost::any) {}
  virtual void visit (CcnbParser::Udata&n, boost::any) {}
  virtual void visit (CcnbParser::Tag&,    boost::any) {}
  virtual void visit (CcnbParser::Dtag&,   boost::any);
  virtual void visit (CcnbParser::Attr& n, boost::any) {}
  virtual void visit (CcnbParser::Dattr&,  boost::any) {}
  virtual void visit (CcnbParser::Ext&  n, boost::any) {}

private:
  void ProcessTag (CcnbParser::BaseTag &n, boost::any param);

private:
  bool m_verbose;
  bool m_signature;
  bool m_minimal;
};

class PlainDecoderException {};

#endif // _CCNB_PLAIN_PRINTER_H_
