/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#include "config.h"
#include "ccnb-print-plain.h"
#include <boost/foreach.hpp>

#include <iostream>

#include "ns3/ccnb-parser-attr.h"
#include "ns3/ccnb-parser-base-attr.h"
#include "ns3/ccnb-parser-base-tag.h"
#include "ns3/ccnb-parser-blob.h"
#include "ns3/ccnb-parser-block.h"
#include "ns3/ccnb-parser-dattr.h"
#include "ns3/ccnb-parser-dtag.h"
#include "ns3/ccnb-parser-ext.h"
#include "ns3/ccnb-parser-tag.h"
#include "ns3/ccnb-parser-udata.h"

#include "ns3/ccnb-parser-name-components-visitor.h"
#include "ns3/ccnb-parser-non-negative-integer-visitor.h"
#include "ns3/ccnb-parser-timestamp-visitor.h"

using namespace std;
using namespace ns3::CcnbParser;

CcnbPlainPrinter::CcnbPlainPrinter ()
{
}

CcnbPlainPrinter::~CcnbPlainPrinter ()
{
}


// just a small helper to avoid duplication
void
CcnbPlainPrinter::ProcessTag (BaseTag &n, boost::any param)
{
  // std::list<Ptr<Block> > n.m_attrs;
  // uint8_t                n.m_encoding; ///< BLOB encoding, possible values NOT_SET=0, UTF8, BASE64
  // std::list<Ptr<Block> > n.m_nestedTags;

  BOOST_FOREACH (Ptr<Block> block, n.m_attrs)
    {
      block->accept (*this, param);
    }
  
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedTags)
    {
      block->accept (*this, param);
    }
}
 
void
CcnbPlainPrinter::visit (Dtag &n, boost::any param)
{
  // uint32_t n.m_dtag;
  static CcnbParser::NameComponentsVisitor nameComponentsVisitor;
  static CcnbParser::NonNegativeIntegerVisitor nonNegativeIntegerVisitor;
  static CcnbParser::TimestampVisitor timestampVisitor;

  switch (n.m_dtag)
    {
    case CcnbParser::CCN_DTAG_Interest:
      cout << ", Packet Type: Interest";
      BOOST_FOREACH (Ptr<Block> nested, n.m_nestedTags)
        nested->accept (*this, param);
      break;
      
    case CcnbParser::CCN_DTAG_ContentObject:
      cout << ", Packet Type: ContentObject";
      BOOST_FOREACH (Ptr<Block> nested, n.m_nestedTags)
        nested->accept (*this, param);
      break;
      
    case CcnbParser::CCN_DTAG_Name:
      cout << ", Name: ";
      if (n.m_nestedTags.size()==0)
        cout << "/";
      BOOST_FOREACH (Ptr<Block> nested, n.m_nestedTags)
        {
          cout << "/";
          nested->accept (nameComponentsVisitor, param);
        }
      break;

    case CcnbParser::CCN_DTAG_Exclude:
      cout << ", Exclude: ";
      
      BOOST_FOREACH (Ptr<Block> nested, n.m_nestedTags)
        {
          cout << "|";
          nested->accept (nameComponentsVisitor, param);
        }
      cout << "|";
      break;
    case CcnbParser::CCN_DTAG_MinSuffixComponents:
      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw CcnbDecodingException ();
      cout << ", MinSuffixComponents: " <<
               boost::any_cast<uint32_t> (
                                          (*n.m_nestedTags.begin())->accept(
                                                                           nonNegativeIntegerVisitor
                                                                           ));
      break;
    case CcnbParser::CCN_DTAG_MaxSuffixComponents:
      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw CcnbDecodingException ();
      cout << ", MaxSuffixComponents: " <<
        boost::any_cast<uint32_t> (
                                          (*n.m_nestedTags.begin())->accept(
                                                                           nonNegativeIntegerVisitor
                                                                           ));
      break;
      
    case CcnbParser::CCN_DTAG_ChildSelector:
      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw CcnbDecodingException ();

      cout << ", ChildSelector: " <<
        boost::any_cast<uint32_t> (
                                   (*n.m_nestedTags.begin())->accept(
                                                                     nonNegativeIntegerVisitor
                                                                     ));
      break;
    case CcnbParser::CCN_DTAG_AnswerOriginKind:
      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw CcnbDecodingException ();
      cout << ", AnswerKind: " <<
        boost::any_cast<uint32_t> (
                                   (*n.m_nestedTags.begin())->accept(
                                                                     nonNegativeIntegerVisitor
                                                                     ));
      break;
    case CcnbParser::CCN_DTAG_Scope: 
      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw CcnbDecodingException ();
      
      cout << ", Scope: " <<
        boost::any_cast<uint32_t> (
                                   (*n.m_nestedTags.begin())->accept(
                                                                     nonNegativeIntegerVisitor
                                                                     ));
      break;
    case CcnbParser::CCN_DTAG_InterestLifetime:
      {
      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw CcnbDecodingException ();

      Time time = boost::any_cast<Time>(n.m_nestedTags.front()->accept (timestampVisitor));

      cout << ", Lifetime: " << time;
      break;
      }
    case CcnbParser::CCN_DTAG_Nonce:
      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw CcnbDecodingException ();

      cout << ", Nonce: ";
      n.m_nestedTags.front()->accept (nameComponentsVisitor, param);
      break;
    }
}
  
// void
// CcnbPlainPrinter::visit (Ext &n, boost::any param)
// {
//   // uint64_t n.m_extSubtype;

//   // no idea how to visualize this attribute...
//   cerr << "*** Warning EXT ["<< n.m_extSubtype <<"] block present\n";
// }
