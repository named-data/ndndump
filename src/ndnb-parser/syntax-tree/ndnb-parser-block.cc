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
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "ns3/ndnb-parser-block.h"

#include "ns3/ndnb-parser-blob.h"
#include "ns3/ndnb-parser-udata.h"
#include "ns3/ndnb-parser-tag.h"
#include "ns3/ndnb-parser-dtag.h"
#include "ns3/ndnb-parser-attr.h"
#include "ns3/ndnb-parser-dattr.h"
#include "ns3/ndnb-parser-ext.h"

namespace ns3 {
namespace NdnbParser {

const uint8_t NDN_TT_BITS = 3;
const uint8_t NDN_TT_MASK = ((1 << NDN_TT_BITS) - 1);
const uint8_t NDN_MAX_TINY= ((1 << (7-NDN_TT_BITS)) - 1);
const uint8_t NDN_TT_HBIT = ((uint8_t)(1 << 7));

Ptr<Block> Block::ParseBlock (Buffer::Iterator &start)
{
  uint32_t value = 0;

  // We will have problems if length field is more than 32 bits. Though it's really impossible
  uint8_t byte = 0;
  while (!(byte & NDN_TT_HBIT))
    {
      value <<= 7;
      value += byte;
      byte = start.ReadU8 ();
    }
  value <<= 4;
  value += ( (byte&(~NDN_TT_HBIT)) >> 3);

  switch (byte & NDN_TT_MASK)
    {
    case NDN_BLOB:
      return Create<Blob> (start, value);
    case NDN_UDATA:
      return Create<Udata> (start, value);
    case NDN_TAG:
      return Create<Tag> (start, value);
    case NDN_ATTR:
      return Create<Attr> (start, value);
    case NDN_DTAG:
      return Create<Dtag> (start, value);
    case NDN_DATTR:
      return Create<Dattr> (start, value);
    case NDN_EXT:
      return Create<Ext> (start, value);
    default:
      throw NdnbDecodingException ();
    }
}

}
}
