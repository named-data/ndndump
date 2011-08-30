/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#include "config.h"
#include "ccnb-print-xml.h"
#include <boost/foreach.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/iostreams/stream.hpp>

#include <iostream>
#include "print-helper.h"

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

using namespace std;
using namespace ns3::CcnbParser;

CcnbPlainPrinter::CcnbPlainPrinter ()
{
}

CcnbPlainPrinter::~CcnbPlainPrinter ()
{
}


size_t
CcnbPlainPrinter::DecodeAndPrint (const char *p, size_t n)
{
  boost::iostreams::stream<boost::iostreams::array_source> in( p, n );

  Ptr<Block> root = Block::ParseBlock (reinterpret_cast<Buffer::Iterator&> (in)); //not a nice hack, but should work
  root->accept (*this, string(""));
}

using namespace boost::archive::iterators;
typedef base64_from_binary<transform_width<string::const_iterator, 6, 8> > base64_t;


//////////////////////////////////////////////////////////////////////

void
CcnbPlainPrinter::visit (Blob &n, boost::any param)
{
  // Buffer n.m_blob;

  if (PrintHelper::is_text_encodable ((unsigned char*)n.m_blob.get (), 0, n.m_blobSize))
    PrintHelper::print_percent_escaped ((unsigned char*)n.m_blob.get (), n.m_blobSize);
  else
    {
      ostreambuf_iterator<char> out_it (cout); // stdout iterator
      // need to encode to base64
      std::copy (base64_t (n.m_blob.get ()),
                 base64_t (n.m_blob.get ()+n.m_blobSize),
                 out_it);
    }
}
 
void
CcnbPlainPrinter::visit (Udata &n, boost::any param)
{
  // std::string n.m_udata;
  cout << n.m_udata;
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

  switch (n.m_dtag)
    {
    case CCN_DTAG_Interest:
      cout << ", Packet Type: Interest";
      break;
    case CCN_DTAG_ContentObject:
      cout << ", Packet Type: ContentObject";
      break;
    case CCN_DTAG_Name:
      cout << ", Name: ";
      n.m_nestedTags->accept (*this, param);
      break;
    }
}
  
void
CcnbPlainPrinter::visit (Ext &n, boost::any param)
{
  // uint64_t n.m_extSubtype;

  // no idea how to visualize this attribute...
  cerr << "*** Warning EXT ["<< n.m_extSubtype <<"] block present\n";
}
