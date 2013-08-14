/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#include "config.h"
#include <iostream>
#include "ndnb-print-plain.h"
#include <boost/foreach.hpp>


#include "ns3/ndnb-parser-attr.h"
#include "ns3/ndnb-parser-base-attr.h"
#include "ns3/ndnb-parser-base-tag.h"
#include "ns3/ndnb-parser-blob.h"
#include "ns3/ndnb-parser-block.h"
#include "ns3/ndnb-parser-dattr.h"
#include "ns3/ndnb-parser-dtag.h"
#include "ns3/ndnb-parser-ext.h"
#include "ns3/ndnb-parser-tag.h"
#include "ns3/ndnb-parser-udata.h"

#include "ns3/ndnb-parser-name-components-visitor.h"
#include "ns3/ndnb-parser-non-negative-integer-visitor.h"
#include "ns3/ndnb-parser-timestamp-visitor.h"

using namespace std;
using namespace ns3::NdnbParser;

NdnbPlainPrinter::NdnbPlainPrinter ()
{
}

NdnbPlainPrinter::~NdnbPlainPrinter ()
{
}


// just a small helper to avoid duplication
void
NdnbPlainPrinter::ProcessTag (BaseTag &n, boost::any param)
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
NdnbPlainPrinter::visit (Dtag &n, boost::any param)
{
  // uint32_t n.m_dtag;
  static NdnbParser::NameComponentsVisitor nameComponentsVisitor;
  static NdnbParser::NonNegativeIntegerVisitor nonNegativeIntegerVisitor;
  static NdnbParser::TimestampVisitor timestampVisitor;

  switch (n.m_dtag)
    {
    case NdnbParser::NDN_DTAG_Interest:
      if (!m_minimal)
        cout << "Packet Type: ";
      cout << "Interest";
      BOOST_FOREACH (Ptr<Block> nested, n.m_nestedTags)
        nested->accept (*this, param);
      break;
      
    case NdnbParser::NDN_DTAG_ContentObject:
      if (!m_minimal)
        cout << "Packet Type: ";
      cout << "ContentObject";
      BOOST_FOREACH (Ptr<Block> nested, n.m_nestedTags)
        nested->accept (*this, param);
      break;
      
    case NdnbParser::NDN_DTAG_Name:
      if (!m_minimal)
        cout << ", Name:";
      cout << " ";
      
      if (n.m_nestedTags.size()==0)
        cout << "/";
      BOOST_FOREACH (Ptr<Block> nested, n.m_nestedTags)
        {
          cout << "/";
          nested->accept (nameComponentsVisitor, param);
        }
      break;

    case NdnbParser::NDN_DTAG_Exclude:
      if (!m_verbose) break;
      
      cout << ", Exclude: ";
      
      BOOST_FOREACH (Ptr<Block> nested, n.m_nestedTags)
        {
          cout << "|";
          nested->accept (nameComponentsVisitor, param);
        }
      cout << "|";
      break;
    case NdnbParser::NDN_DTAG_MinSuffixComponents:
      if (!m_verbose) break;

      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw NdnbDecodingException ();
      cout << ", MinSuffixComponents: " <<
               boost::any_cast<uint32_t> (
                                          (*n.m_nestedTags.begin())->accept(
                                                                           nonNegativeIntegerVisitor
                                                                           ));
      break;
    case NdnbParser::NDN_DTAG_MaxSuffixComponents:
      if (!m_verbose) break;

      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw NdnbDecodingException ();
      cout << ", MaxSuffixComponents: " <<
        boost::any_cast<uint32_t> (
                                          (*n.m_nestedTags.begin())->accept(
                                                                           nonNegativeIntegerVisitor
                                                                           ));
      break;

    case NdnbParser::NDN_DTAG_PublisherPublicKeyDigest:
      if (!m_verbose) break;
      cout << ", PublisherPublicKeyDigest: ";
      BOOST_FOREACH (Ptr<Block> nested, n.m_nestedTags)
          nested->accept (nameComponentsVisitor, param);
      break;
    case NdnbParser::NDN_DTAG_PublisherCertificateDigest:
      if (!m_verbose) break;
      cout << ", PublisherCertificateDigest: ";
      BOOST_FOREACH (Ptr<Block> nested, n.m_nestedTags)
          nested->accept (nameComponentsVisitor, param);
      break;
    case NdnbParser::NDN_DTAG_PublisherIssuerKeyDigest:
      if (!m_verbose) break;
      cout << ", PublisherIssuerKeyDigest: ";
      BOOST_FOREACH (Ptr<Block> nested, n.m_nestedTags)
          nested->accept (nameComponentsVisitor, param);
      break;
    case NdnbParser::NDN_DTAG_PublisherIssuerCertificateDigest:
      if (!m_verbose) break;
      cout << ", PublisherIssuerCertificateDigest: ";
      BOOST_FOREACH (Ptr<Block> nested, n.m_nestedTags)
          nested->accept (nameComponentsVisitor, param);
      break;           
    case NdnbParser::NDN_DTAG_ChildSelector:
      if (!m_verbose) break;

      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw NdnbDecodingException ();

      cout << ", ChildSelector: " <<
        boost::any_cast<uint32_t> (
                                   (*n.m_nestedTags.begin())->accept(
                                                                     nonNegativeIntegerVisitor
                                                                     ));
      break;
    case NdnbParser::NDN_DTAG_AnswerOriginKind:
      if (!m_verbose) break;

      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw NdnbDecodingException ();
      cout << ", AnswerKind: " <<
        boost::any_cast<uint32_t> (
                                   (*n.m_nestedTags.begin())->accept(
                                                                     nonNegativeIntegerVisitor
                                                                     ));
      break;
    case NdnbParser::NDN_DTAG_Scope: 
      if (!m_verbose) break;

      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw NdnbDecodingException ();
      
      cout << ", Scope: " <<
        boost::any_cast<uint32_t> (
                                   (*n.m_nestedTags.begin())->accept(
                                                                     nonNegativeIntegerVisitor
                                                                     ));
      break;
    case NdnbParser::NDN_DTAG_InterestLifetime:
      {
      if (m_minimal) break;

      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw NdnbDecodingException ();

      Time time = boost::any_cast<Time>(n.m_nestedTags.front()->accept (timestampVisitor));

      cout << ", Lifetime: " << time;
      break;
      }
    case NdnbParser::NDN_DTAG_Nonce:
      if (m_minimal) break;

      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw NdnbDecodingException ();

      cout << ", Nonce: ";
      n.m_nestedTags.front()->accept (nameComponentsVisitor, param);
      break;
    }
}
  
// void
// NdnbPlainPrinter::visit (Ext &n, boost::any param)
// {
//   // uint64_t n.m_extSubtype;

//   // no idea how to visualize this attribute...
//   cerr << "*** Warning EXT ["<< n.m_extSubtype <<"] block present\n";
// }
