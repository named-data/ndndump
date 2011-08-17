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

using namespace std;

CcnbXmlPrinter::CcnbXmlPrinter (int formatting_flags, const ccn_dict *dtags)
{
  // m_schema = CCN_NO_SCHEMA;
  m_tagdict = dtags->dict;
  m_tagdict_count = dtags->count;
  m_formatting_flags = formatting_flags;
}

CcnbXmlPrinter::~CcnbXmlPrinter ()
{
}


size_t
CcnbXmlPrinter::DecodeAndPrint (const char *p, size_t n)
{
  boost::iostreams::stream<boost::iostreams::array_source> in( p, n );

  Ptr<Block> root = Block::ParseBlock (reinterpret_cast<Buffer::Iterator&> (in)); //not a nice hack, but should work
}


using namespace boost::archive::iterators;
typedef base64_from_binary<transform_width<string::const_iterator, 6, 8> > base64_t;

void
CcnbXmlPrinter::visit (Blob &n)
{
  // Buffer n.m_blob;

  ostreambuf_iterator<char> out_it (cout); // stdout iterator
  // need to encode to base64
  std::copy (base64_t (n.m_blob.get()),
             base64_t (n.m_blob.get()+n.m_blobSize),
             out_it);
}
 
void
CcnbXmlPrinter::visit (Udata &n)
{
  // std::string n.m_udata;
  cout << n.m_udata;
}

// just a small helper to avoid duplication
void
CcnbXmlPrinter::ProcessTag (BaseTag &n)
{
  // std::list<Ptr<Block> > n.m_attrs;
  // uint8_t                n.m_encoding; ///< BLOB encoding, possible values NOT_SET=0, UTF8, BASE64
  // std::list<Ptr<Block> > n.m_nestedTags;

  BOOST_FOREACH (Ptr<Block> block, n.m_attrs)
    {
      block->accept (*this);
    }

  switch (n.m_encoding)
    {
    case BaseTag::UTF8:
      cout << " ccnbencoding=\"text\"";
      break;
    case BaseTag::BASE64:
      cout << " ccnbencoding=\"base64Binary\"";
      break;
    default:
      break;
    }
  cout << ">";
  
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedTags)
    {
      block->accept (*this);
    }
}

void
CcnbXmlPrinter::visit (Tag &n)
{
  // std::string n.m_tag;
  cout << "<" << n.m_tag;

  ProcessTag (n);

  cout << "</" << n.m_tag << ">";
}
 
void
CcnbXmlPrinter::visit (Dtag &n)
{
  // uint32_t n.m_dtag;
  string tagName;
  try
    {
      tagName = PrintHelper::dict_name_from_number (n.m_dtag, m_tagdict, m_tagdict_count);
    }
  catch (UnknownDtag)
    {
      cerr << "*** Warning: unrecognized DTAG [" << n.m_dtag << "]\n";
      tagName = "UNKNOWN_DTAG";
    }

  cout << "<" << tagName;

  ProcessTag (n);

  cout << "</" << tagName << ">";
}
 
void
CcnbXmlPrinter::visit (Attr &n)
{
  // std::string n.m_attr;
  // Ptr<Udata> n.m_value;

  cout << " " << n.m_attr << "=\"";
  n.accept (*this);
  cout << "\"";
}
 
void
CcnbXmlPrinter::visit (Dattr &n)
{
  // uint32_t n.m_dattr;
  // Ptr<Udata> n.m_value;

  cerr << "*** Warning: unrecognized DATTR [" << n.m_dattr << "]\n";
  cout << " UNKNOWN_ATTR=\"";
  n.accept (*this);
  cout << "\"";
}
 
void
CcnbXmlPrinter::visit (Ext &n)
{
  // uint64_t n.m_extSubtype;

  // no idea how to visualize this attribute...
  cerr << "*** Warning EXT ["<< n.m_extSubtype <<"] block present\n";
}
