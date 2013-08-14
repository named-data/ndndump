/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#include "config.h"
#include <iostream>
#include "ndnb-print-xml.h"
#include <boost/foreach.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/iterator/transform_iterator.hpp>
#include <boost/archive/iterators/dataflow_exception.hpp>

#include <boost/iostreams/stream.hpp>

#include "print-helper.h"

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

using namespace std;
using namespace ns3::NdnbParser;

NdnbXmlPrinter::NdnbXmlPrinter (int formatting_flags, const ndn_dict *dtags)
{
  // m_schema = NDN_NO_SCHEMA;
  m_tagdict = dtags->dict;
  m_tagdict_count = dtags->count;
  m_formatting_flags = formatting_flags;
}

NdnbXmlPrinter::~NdnbXmlPrinter ()
{
}


size_t
NdnbXmlPrinter::DecodeAndPrint (const char *p, size_t n)
{
  boost::iostreams::stream<boost::iostreams::array_source> in( p, n );

  Ptr<Block> root = Block::ParseBlock (reinterpret_cast<Buffer::Iterator&> (in)); //not a nice hack, but should work
  root->accept (*this, string(""));
  return n;
}

using namespace boost::archive::iterators;
using namespace boost;


// typedef base64_from_binary<transform_width<string::const_iterator, 6, 8> > base64_t;

template<class CharType>
struct hex_from_4_bit
{
  typedef CharType result_type;
  CharType operator () (CharType ch) const
  {
    const char *lookup_table = "0123456789abcdef";
    // cout << "New character: " << (int) ch << " (" << (char) ch << ")" << "\n";
    BOOST_ASSERT (ch < 16);
    return lookup_table[static_cast<size_t>(ch)];
  }
};

typedef transform_iterator<hex_from_4_bit<string::const_iterator::value_type>,
                           transform_width<string::const_iterator, 4, 8, string::const_iterator::value_type> > string_from_binary;


//////////////////////////////////////////////////////////////////////

void
NdnbXmlPrinter::visit (Blob &n, boost::any param)
{
  // Buffer n.m_blob;
  // std::cout << "===" << n.m_blobSize << ", " << (int)n.m_blob.get ()[0] << "===";
  if (n.m_blobSize > 0)
    {
      if (PrintHelper::is_text_encodable ((unsigned char*)n.m_blob.get (), 0, n.m_blobSize))
        PrintHelper::print_percent_escaped (cout, (unsigned char*)n.m_blob.get (), n.m_blobSize);
      else
        {
          ostreambuf_iterator<char> out_it (cout); // stdout iterator

          copy (string_from_binary (n.m_blob.get ()),
                string_from_binary (n.m_blob.get ()+n.m_blobSize),
                out_it);

          // need to encode to base64
          // std::copy (base64_t (n.m_blob.get ()),
          //            base64_t (n.m_blob.get ()+n.m_blobSize),
          //            out_it);
        }
    }
}
 
void
NdnbXmlPrinter::visit (Udata &n, boost::any param)
{
  // std::string n.m_udata;
  cout << n.m_udata;
}

// just a small helper to avoid duplication
void
NdnbXmlPrinter::ProcessTag (BaseTag &n, boost::any param)
{
  // std::list<Ptr<Block> > n.m_attrs;
  // uint8_t                n.m_encoding; ///< BLOB encoding, possible values NOT_SET=0, UTF8, BASE64
  // std::list<Ptr<Block> > n.m_nestedTags;

  BOOST_FOREACH (Ptr<Block> block, n.m_attrs)
    {
      block->accept (*this, param);
    }

  cout << ">";
  if (!(n.m_nestedTags.size()==1 &&
       (DynamicCast<Blob>(n.m_nestedTags.front()) || DynamicCast<Udata>(n.m_nestedTags.front()))))
    {
      cout << endl;
    }
  
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedTags)
    {
      block->accept (*this, param);
    }
}

void
NdnbXmlPrinter::visit (Tag &n, boost::any param)
{
  // std::string n.m_tag;
  cout << boost::any_cast<string>(param) << "<" << n.m_tag; 

  ProcessTag (n, boost::any_cast<string>(param)+"  ");

  if (!(n.m_nestedTags.size()==1 &&
       (DynamicCast<Blob>(n.m_nestedTags.front()) || DynamicCast<Udata>(n.m_nestedTags.front()))))
    {
      cout << boost::any_cast<string>(param);
    }

  cout << "</" << n.m_tag << ">" << endl;
}
 
void
NdnbXmlPrinter::visit (Dtag &n, boost::any param)
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

  cout << boost::any_cast<string>(param) << "<" << tagName;

  ProcessTag (n, boost::any_cast<string>(param) + "  ");

  if (!(n.m_nestedTags.size()==1 &&
       (DynamicCast<Blob>(n.m_nestedTags.front()) || DynamicCast<Udata>(n.m_nestedTags.front()))))
    {
      cout << boost::any_cast<string>(param);
    }

  cout << "</" << tagName << ">" << endl;
}
 
void
NdnbXmlPrinter::visit (Attr &n, boost::any param)
{
  // std::string n.m_attr;
  // Ptr<Udata> n.m_value;

  cout << " " << n.m_attr << "=\"";
  n.accept (*this, param);
  cout << "\"";
}
 
void
NdnbXmlPrinter::visit (Dattr &n, boost::any param)
{
  // uint32_t n.m_dattr;
  // Ptr<Udata> n.m_value;

  cerr << "*** Warning: unrecognized DATTR [" << n.m_dattr << "]\n";
  cout << " UNKNOWN_ATTR=\"";
  n.accept (*this, param);
  cout << "\"";
}
 
void
NdnbXmlPrinter::visit (Ext &n, boost::any param)
{
  // uint64_t n.m_extSubtype;

  // no idea how to visualize this attribute...
  cerr << "*** Warning EXT ["<< n.m_extSubtype <<"] block present\n";
}
