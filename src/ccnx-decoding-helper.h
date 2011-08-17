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

#ifndef _CCNX_DECODING_HELPER_H_
#define _CCNX_DECODING_HELPER_H_

#include <sys/types.h>
#include <boost/any.hpp>
#include <boost/shared_ptr.hpp>
#include <istream>
#include <list>

class Block;
class Blob;
class Udata;
class Tag;
class Attr;
class Dtag;
class Dattr;
class Ext;

// A couple of routines to make code compatible with NS-3
#define Ptr boost::shared_ptr
// template<class T>
// class Ptr : public boost::shared_ptr<T> { };

#define NOT_NS3 1 // there is a totally incompatible code :(

template<class T>
boost::shared_ptr<T> Create() { return boost::shared_ptr<T> (new T()); }

template<class T, class P1>
boost::shared_ptr<T> Create(P1 &p1) { return boost::shared_ptr<T> (new T(p1)); }

template<class T, class P1, class P2>
boost::shared_ptr<T> Create(P1 &p1, P2 p2) { return boost::shared_ptr<T> (new T(p1, p2)); }

template<class T, class P1, class P2, class P3>
boost::shared_ptr<T> Create(P1 &p1, P2 p2, P3 p3) { return boost::shared_ptr<T> (new T(p1, p2, p3)); }

//template<class To, class From>
//boost::shared_ptr<T> StaticCast (From &
template<class T, class U>
boost::shared_ptr<T> StaticCast(boost::shared_ptr<U> const & r) { return boost::static_pointer_cast<T>(r); }

template<class T, class U>
boost::shared_ptr<T> DynamicCast(boost::shared_ptr<U> const & r) { return boost::dynamic_pointer_cast<T>(r); }

typedef unsigned char uint8_t; // types.h defines  u_char

class Buffer : public boost::shared_ptr<char>
{
public:
  class Iterator : public std::istream
  {
  public:
    uint8_t ReadU8 () { return static_cast<uint8_t> (get ()); }
    uint8_t PeekU8 () { return static_cast<uint8_t> (peek ()); }
    bool IsEnd () const { return eof(); }
  };

  
};
// Done

class Visitor
{
public:
  virtual void visit (Blob& )=0;
  virtual void visit (Udata&)=0;
  virtual void visit (Tag&  )=0;
  virtual void visit (Attr& )=0;
  virtual void visit (Dtag& )=0;
  virtual void visit (Dattr&)=0;
  virtual void visit (Ext&  )=0;
};
  
class GJVisitor
{
public:
  virtual boost::any visit (Blob&,  boost::any)=0;
  virtual boost::any visit (Udata&, boost::any)=0;
  virtual boost::any visit (Tag&,   boost::any)=0;
  virtual boost::any visit (Attr&,  boost::any)=0;
  virtual boost::any visit (Dtag&,  boost::any)=0;
  virtual boost::any visit (Dattr&, boost::any)=0;
  virtual boost::any visit (Ext&,   boost::any)=0;
};
  
class GJNoArguVisitor
{
public:
  virtual boost::any visit (Blob& )=0;
  virtual boost::any visit (Udata&)=0;
  virtual boost::any visit (Tag&  )=0;
  virtual boost::any visit (Attr& )=0;
  virtual boost::any visit (Dtag& )=0;
  virtual boost::any visit (Dattr&)=0;
  virtual boost::any visit (Ext&  )=0;
};

class GJVoidVisitor
{
public:
  virtual void visit (Blob&,  boost::any)=0;
  virtual void visit (Udata&, boost::any)=0;
  virtual void visit (Tag&,   boost::any)=0;
  virtual void visit (Attr&,  boost::any)=0;
  virtual void visit (Dtag&,  boost::any)=0;
  virtual void visit (Dattr&, boost::any)=0;
  virtual void visit (Ext&,   boost::any)=0;
};

  
class Block
{
public:
  /**
   * Parsing block header and creating an appropriate object
   */
  static Ptr<Block>
  ParseBlock (Buffer::Iterator &start);
  
  virtual void accept( Visitor &v )                           =0;
  virtual void accept (GJVoidVisitor &v, boost::any param)    =0;
  virtual boost::any accept( GJNoArguVisitor &v )             =0;
  virtual boost::any accept( GJVisitor &v, boost::any param ) =0;
};

class Blob : public Block
{
public:
  Blob (Buffer::Iterator &start, uint32_t length);
  
  virtual void accept( Visitor &v )                           { v.visit( *this ); }
  virtual void accept( GJVoidVisitor &v, boost::any param )   { v.visit( *this, param ); }
  virtual boost::any accept( GJNoArguVisitor &v )             { return v.visit( *this ); }
  virtual boost::any accept( GJVisitor &v, boost::any param ) { return v.visit( *this, param ); }

#ifndef NOT_NS3
  Buffer m_blob;
#else
  Ptr<char> m_blob;
#endif
};

class Udata : public Block
{
public:
  Udata (Buffer::Iterator &start, uint32_t length);
  
  virtual void accept( Visitor &v )                           { v.visit( *this ); }
  virtual void accept( GJVoidVisitor &v, boost::any param )   { v.visit( *this, param ); }
  virtual boost::any accept( GJNoArguVisitor &v )             { return v.visit( *this ); }
  virtual boost::any accept( GJVisitor &v, boost::any param ) { return v.visit( *this, param ); }

  std::string m_udata;
};

class Tag : public Block
{
public:
  Tag (Buffer::Iterator &start, uint32_t length);

  virtual void accept( Visitor &v )                           { v.visit( *this ); }
  virtual void accept( GJVoidVisitor &v, boost::any param )   { v.visit( *this, param ); }
  virtual boost::any accept( GJNoArguVisitor &v )             { return v.visit( *this ); }
  virtual boost::any accept( GJVisitor &v, boost::any param ) { return v.visit( *this, param ); }

  std::string m_tag;
  std::list<Ptr<Block> > m_nestedBlocks;
};

class Attr : public Block
{
public:
  Attr (Buffer::Iterator &start, uint32_t length);
  
  virtual void accept( Visitor &v )                           { v.visit( *this ); }
  virtual void accept( GJVoidVisitor &v, boost::any param )   { v.visit( *this, param ); }
  virtual boost::any accept( GJNoArguVisitor &v )             { return v.visit( *this ); }
  virtual boost::any accept( GJVisitor &v, boost::any param ) { return v.visit( *this, param ); }

  std::string m_attr;
  Ptr<Udata> m_value;
};

class Dtag : public Block
{
public:
  Dtag (Buffer::Iterator &start, uint32_t dtag);

  virtual void accept( Visitor &v )                           { v.visit( *this ); }
  virtual void accept( GJVoidVisitor &v, boost::any param )   { v.visit( *this, param ); }
  virtual boost::any accept( GJNoArguVisitor &v )             { return v.visit( *this ); }
  virtual boost::any accept( GJVisitor &v, boost::any param ) { return v.visit( *this, param ); }

  uint32_t m_dtag;
  std::list<Ptr<Block> > m_nestedBlocks;
};

class Dattr : public Block
{
public:
  Dattr (Buffer::Iterator &start, uint32_t dattr);

  virtual void accept( Visitor &v )                           { v.visit( *this ); }
  virtual void accept( GJVoidVisitor &v, boost::any param )   { v.visit( *this, param ); }
  virtual boost::any accept( GJNoArguVisitor &v )             { return v.visit( *this ); }
  virtual boost::any accept( GJVisitor &v, boost::any param ) { return v.visit( *this, param ); }

  uint32_t m_dattr;
  Ptr<Udata> m_value;
};

class Ext : public Block
{
public:
  Ext (Buffer::Iterator &start, uint32_t extSubtype);

  virtual void accept( Visitor &v )                           { v.visit( *this ); }
  virtual void accept( GJVoidVisitor &v, boost::any param )   { v.visit( *this, param ); }
  virtual boost::any accept( GJNoArguVisitor &v )             { return v.visit( *this ); }
  virtual boost::any accept( GJVisitor &v, boost::any param ) { return v.visit( *this, param ); }

  uint64_t m_extSubtype;
};

class DepthFirstVisitor : public Visitor
{
public:
  virtual void visit (Blob& );
  virtual void visit (Udata&);
  virtual void visit (Tag&  );
  virtual void visit (Attr& );
  virtual void visit (Dtag& );
  virtual void visit (Dattr&);
  virtual void visit (Ext&  );
};

class GJDepthFirstVisitor : public GJVisitor
{
public:
  virtual boost::any visit (Blob&,  boost::any);
  virtual boost::any visit (Udata&, boost::any);
  virtual boost::any visit (Tag&,   boost::any);
  virtual boost::any visit (Attr&,  boost::any);
  virtual boost::any visit (Dtag&,  boost::any);
  virtual boost::any visit (Dattr&, boost::any);
  virtual boost::any visit (Ext&,   boost::any);
};

class GJNoArguDepthFirstVisitor : public GJNoArguVisitor
{
public:
  virtual boost::any visit (Blob& );
  virtual boost::any visit (Udata&);
  virtual boost::any visit (Tag&  );
  virtual boost::any visit (Attr& );
  virtual boost::any visit (Dtag& );
  virtual boost::any visit (Dattr&);
  virtual boost::any visit (Ext&  );
};

class GJVoidDepthFirstVisitor : public GJVoidVisitor
{
public:
  virtual void visit (Blob&,  boost::any);
  virtual void visit (Udata&, boost::any);
  virtual void visit (Tag&,   boost::any);
  virtual void visit (Attr&,  boost::any);
  virtual void visit (Dtag&,  boost::any);
  virtual void visit (Dattr&, boost::any);
  virtual void visit (Ext&,   boost::any);
};


/**
 * \brief Visitor to get nonNegativeIntegers from UDATA blocks
 *
 * Only UDATA elements are processed. Everything else returns empty boost::any()
 */
class NonNegativeIntegerVisitor : public GJNoArguDepthFirstVisitor
{
public:
  virtual boost::any visit (Udata &n);
};

/**
 * \brief Visitor to get strings from UDATA blocks
 *
 * Returns strings from UDATA blocks. Everything else returns empty boost::any()
 */
class StringVisitor : public GJNoArguDepthFirstVisitor
{
public:
  virtual boost::any visit (Udata &n);
};

class CcnxDecodingException {};

#endif // _CCNX_DECODING_HELPER_H_

