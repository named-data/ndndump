/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2011 University of California, Los Angeles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: 
 */

#include "ccnx-decoding-helper.h"

#include <sstream>
#include <boost/foreach.hpp>
#include <boost/iostreams/read.hpp>

namespace Ccnx // again, add compatibility with NS-3 code
{
extern "C"
{
#include <ccn/coding.h>
} // extern "C"

#undef CCN_CLOSE
const uint8_t CCN_CLOSE = 0x00;
} // namespace Ccnx

// const uint8_t CCN_TT_BITS = 3;
// const uint8_t CCN_TT_MASK = ((1 << CCN_TT_BITS) - 1);
// const uint8_t CCN_MAX_TINY= ((1 << (7-CCN_TT_BITS)) - 1);
// const uint8_t CCN_TT_HBIT = ((uint8_t)(1 << 7));

Ptr<Block> Block::ParseBlock (Buffer::Iterator &start)
{
  uint32_t value = 0;

  // We will have problems if length field is more than 32 bits. Though it's really impossible
  uint8_t byte = 0;
  while (!(byte & CCN_TT_HBIT))
    {
      value <<= 8;
      value += byte;
      byte = start.ReadU8 ();
    }
  value <<= 4;
  value += ( (byte&(~CCN_TT_HBIT)) >> 3);

  switch (byte & CCN_TT_MASK)
    {
    case Ccnx::CCN_BLOB:
      return Create<Blob> (start, value);
    case Ccnx::CCN_UDATA:
      return Create<Udata> (start, value);
    case Ccnx::CCN_TAG:
      return Create<Tag> (start, value);
    case Ccnx::CCN_ATTR:
      return Create<Attr> (start, value);
    case Ccnx::CCN_DTAG:
      return Create<Dtag> (start, value);
    case Ccnx::CCN_DATTR:
      return Create<Dattr> (start, value);
    case Ccnx::CCN_EXT:
      return Create<Ext> (start, value);
    default:
      throw CcnxDecodingException ();
    }
}

Blob::Blob (Buffer::Iterator &start, uint32_t length)
{
#ifndef NOT_NS3
  start.Read (m_blob.Begin (), length);
#else
  m_blob = boost::shared_ptr<char> (new char[length]);
  uint32_t read = boost::iostreams::read (start, m_blob.get (), length);
  if (read!=length)
    throw CcnxDecodingException ();
#endif
}

Udata::Udata (Buffer::Iterator &start, uint32_t length)
{
  m_udata.reserve (length+1); //just in case we will need \0 at the end later
  // this is actually the way Read method is implemented in network/src/buffer.cc
  for (uint32_t i = 0; i < length; i++)
    {
      m_udata.append (reinterpret_cast<const char*>(start.ReadU8 ()));
    }
}

// length length in octets of UTF-8 encoding of tag name - 1 (minimum tag name length is 1) 
Tag::Tag (Buffer::Iterator &start, uint32_t length)
{
  m_tag.reserve (length+2); // extra byte for potential \0 at the end
  for (uint32_t i = 0; i < (length+1); i++)
    {
      m_tag.append (reinterpret_cast<const char*>(start.ReadU8 ()));
    }
  
  while (!start.IsEnd () && start.PeekU8 ()!=Ccnx::CCN_CLOSE)
    {
      m_nestedBlocks.push_back (Block::ParseBlock (start));
    }
  if (start.IsEnd ())
      throw CcnxDecodingException ();

  start.ReadU8 (); // read CCN_CLOSE
}

// length length in octets of UTF-8 encoding of tag name - 1 (minimum tag name length is 1) 
Attr::Attr (Buffer::Iterator &start, uint32_t length)
{
  m_attr.reserve (length+2); // extra byte for potential \0 at the end
  for (uint32_t i = 0; i < (length+1); i++)
    {
      m_attr.append (reinterpret_cast<const char*>(start.ReadU8 ()));
    }
  m_value = DynamicCast<Udata> (Block::ParseBlock (start));
  if (m_value == 0)
    throw CcnxDecodingException (); // "ATTR must be followed by UDATA field"
}

Dtag::Dtag (Buffer::Iterator &start, uint32_t dtag)
{
  m_dtag = dtag;

#ifndef NOT_NS3  
  /**
   * Hack
   *
   * Stop processing after encountering <Content> dtag.  Actual
   * content (including virtual payload) will be stored in Packet
   * buffer
   */
  if (dtag == Ccnx::CCN_DTAG_Content)
    return; // hack #1. Do not process nesting block for <Content>
#endif
  
  while (!start.IsEnd () && start.PeekU8 ()!=Ccnx::CCN_CLOSE)
    {
      m_nestedBlocks.push_back (Block::ParseBlock (start));

#ifndef NOT_NS3
      // hack #2. Stop processing nested blocks if last block was <Content>
      if (m_dtag == Ccnx::CCN_DTAG_ContentObject && // we are in <ContentObject>
          DynamicCast<Dtag> (m_nestedBlocks.back())!=0 && // last block is DTAG
          DynamicCast<Dtag> (m_nestedBlocks.back())->m_dtag == Ccnx::CCN_DTAG_Content) 
        {
          return; 
        }
#endif
    }
  if (start.IsEnd ())
      throw CcnxDecodingException ();

  start.ReadU8 (); // read CCN_CLOSE
}

// dictionary attributes are not used (yet?) in CCNx 
Dattr::Dattr (Buffer::Iterator &start, uint32_t dattr)
{
  m_dattr = dattr;
  m_value = DynamicCast<Udata> (Block::ParseBlock (start));
  if (m_value == 0)
    throw CcnxDecodingException (); // "ATTR must be followed by UDATA field"
}

Ext::Ext (Buffer::Iterator &start, uint32_t extSubtype)
{
  m_extSubtype = extSubtype;
}

void
DepthFirstVisitor::visit (Blob &n)
{
  // Buffer n.m_blob;
}
 
void
DepthFirstVisitor::visit (Udata &n)
{
  // std::string n.m_udata;
}
 
void
DepthFirstVisitor::visit (Tag &n)
{
  // std::string n.m_tag;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedBlocks)
    {
      block->accept (*this);
    }
}
 
void
DepthFirstVisitor::visit (Attr &n)
{
  // std::string n.m_attr;
  // Ptr<Udata> n.m_value;
}
 
void
DepthFirstVisitor::visit (Dtag &n)
{
  // uint32_t n.m_dtag;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedBlocks)
    {
      block->accept (*this);
    }
}
 
void
DepthFirstVisitor::visit (Dattr &n)
{
  // uint32_t n.m_dattr;
  // Ptr<Udata> n.m_value;
}
 
void
DepthFirstVisitor::visit (Ext &n)
{
  // uint64_t n.m_extSubtype;
}

//////////////////////////////////////////////////////////////////////
 
boost::any
GJNoArguDepthFirstVisitor::visit (Blob &n)
{
  // Buffer n.m_blob;
  return n.m_blob;
}
 
boost::any
GJNoArguDepthFirstVisitor::visit (Udata &n)
{
  // std::string n.m_udata;
  return n.m_udata;
}
 
boost::any
GJNoArguDepthFirstVisitor::visit (Tag &n)
{
  // std::string n.m_tag;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedBlocks)
    {
      block->accept (*this);
    }
  return boost::any();
}
 
boost::any
GJNoArguDepthFirstVisitor::visit (Attr &n)
{
  // std::string n.m_attr;
  // Ptr<Udata> n.m_value;
  return boost::any(
                    std::pair<std::string,std::string> (
                                                        n.m_attr,
                                                        boost::any_cast<std::string> (n.m_value->accept (*this))
                                                        ));
}
 
boost::any
GJNoArguDepthFirstVisitor::visit (Dtag &n)
{
  // uint32_t n.m_dtag;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedBlocks)
    {
      block->accept (*this);
    }
  return boost::any();
}
 
boost::any
GJNoArguDepthFirstVisitor::visit (Dattr &n)
{
  // uint32_t n.m_dattr;
  // Ptr<Udata> n.m_value;
  return boost::any(
                    std::pair<uint32_t,std::string> (
                                                     n.m_dattr,
                                                     boost::any_cast<std::string> (n.m_value->accept (*this))
                                                     ));
}
 
boost::any
GJNoArguDepthFirstVisitor::visit (Ext &n)
{
  // uint64_t n.m_extSubtype;
  return n.m_extSubtype;
}

//////////////////////////////////////////////////////////////////////

void
GJVoidDepthFirstVisitor::visit (Blob &n, boost::any param)
{
  // Buffer n.m_blob;
}
 
void
GJVoidDepthFirstVisitor::visit (Udata &n, boost::any param)
{
  // std::string n.m_udata;
}
 
void
GJVoidDepthFirstVisitor::visit (Tag &n, boost::any param)
{
  // std::string n.m_tag;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedBlocks)
    {
      block->accept (*this, param);
    }
}
 
void
GJVoidDepthFirstVisitor::visit (Attr &n, boost::any param)
{
  // std::string n.m_attr;
  // Ptr<Udata> n.m_value;
}
 
void
GJVoidDepthFirstVisitor::visit (Dtag &n, boost::any param)
{
  // uint32_t n.m_dtag;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedBlocks)
    {
      block->accept (*this, param);
    }
}
 
void
GJVoidDepthFirstVisitor::visit (Dattr &n, boost::any param)
{
  // uint32_t n.m_dattr;
  // Ptr<Udata> n.m_value;
}
 
void
GJVoidDepthFirstVisitor::visit (Ext &n, boost::any param)
{
  // uint64_t n.m_extSubtype;
}

//////////////////////////////////////////////////////////////////////
 
boost::any
GJDepthFirstVisitor::visit (Blob &n, boost::any param)
{
  // Buffer n.m_blob;
  return n.m_blob;
}
 
boost::any
GJDepthFirstVisitor::visit (Udata &n, boost::any param)
{
  // std::string n.m_udata;
  return n.m_udata;
}
 
boost::any
GJDepthFirstVisitor::visit (Tag &n, boost::any param)
{
  // std::string n.m_tag;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedBlocks)
    {
      block->accept (*this, param);
    }
  return boost::any();
}
 
boost::any
GJDepthFirstVisitor::visit (Attr &n, boost::any param)
{
  // std::string n.m_attr;
  // Ptr<Udata> n.m_value;
  return boost::any(
                    std::pair<std::string,std::string> (
                                                        n.m_attr,
                                                        boost::any_cast<std::string> (n.m_value->accept (*this,param))
                                                        ));
}
 
boost::any
GJDepthFirstVisitor::visit (Dtag &n, boost::any param)
{
  // uint32_t n.m_dtag;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedBlocks)
    {
      block->accept (*this, param);
    }
  return boost::any();
}
 
boost::any
GJDepthFirstVisitor::visit (Dattr &n, boost::any param)
{
  // uint32_t n.m_dattr;
  // Ptr<Udata> n.m_value;
  return boost::any(
                    std::pair<uint32_t,std::string> (
                                                     n.m_dattr,
                                                     boost::any_cast<std::string> (n.m_value->accept (*this,param))
                                                     ));
}
 
boost::any
GJDepthFirstVisitor::visit (Ext &n, boost::any param)
{
  // uint32_t n.m_extSubtype;
  return n.m_extSubtype;
}

//////////////////////////////////////////////////////////////////////

boost::any
NonNegativeIntegerVisitor::visit (Udata &n)
{
  // std::string n.m_udata;
  std::istringstream is (n.m_udata);
  int32_t value;
  is >> value;
  if (value<0) // value should be non-negative
    throw CcnxDecodingException ();

  return static_cast<uint32_t> (value);
}


//////////////////////////////////////////////////////////////////////

boost::any
StringVisitor::visit (Udata &n)
{
  // std::string n.m_udata;
  return n.m_udata;
}

