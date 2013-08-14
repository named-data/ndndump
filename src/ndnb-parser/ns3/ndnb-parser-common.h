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

#ifndef _NDNB_PARSER_COMMON_H_
#define _NDNB_PARSER_COMMON_H_

namespace ns3 {

/**
 * \ingroup ndnx
 * \defgroup ndnx-ndnb NDNB decoding routines
 */
/**
 * \ingroup ndnx-ndnb
 * \brief Namespace for ndnb parer
 */
namespace NdnbParser {

// forward declarations
class Block;
class Blob;
class Udata;
class Tag;
class Attr;
class Dtag;
class Dattr;
class Ext;
class BaseTag;
class BaseAttr;

/**
 * \brief Exception thrown if there is a parsing error
 *
 * \todo inherit this class from some exception class and provide meaningful error messages
 */
class NdnbDecodingException {};

/**
 * \brief Type tag for a ndnb start marker.
 *
 * \see http://www.ndnx.org/releases/latest/doc/technical/DTAG.html
 */
enum ndn_tt {
  NDN_EXT,        /**< starts composite extension - numval is subtype */
  NDN_TAG,        /**< starts composite - numval is tagnamelen-1 */
  NDN_DTAG,       /**< starts composite - numval is tagdict index (enum ndn_dtag) */
  NDN_ATTR,       /**< attribute - numval is attrnamelen-1, value follows */
  NDN_DATTR,      /**< attribute numval is attrdict index */
  NDN_BLOB,       /**< opaque binary data - numval is byte count */
  NDN_UDATA,      /**< UTF-8 encoded character data - numval is byte count */
  NDN_NO_TOKEN    /**< should not occur in encoding */
};

/** \brief NDN_CLOSE terminates composites */
enum {NDN_CLOSE = 0};

/**
 * \brief DTAG identifies ndnb-encoded elements.
 *
 * \see http://www.ndnx.org/releases/latest/doc/technical/DTAG.html
 */
enum ndn_dtag {
  NDN_DTAG_Any = 13,
  NDN_DTAG_Name = 14,
  NDN_DTAG_Component = 15,
  NDN_DTAG_Certificate = 16,
  NDN_DTAG_Collection = 17,
  NDN_DTAG_CompleteName = 18,
  NDN_DTAG_Content = 19,
  NDN_DTAG_SignedInfo = 20,
  NDN_DTAG_ContentDigest = 21,
  NDN_DTAG_ContentHash = 22,
  NDN_DTAG_Count = 24,
  NDN_DTAG_Header = 25,
  NDN_DTAG_Interest = 26,	/* 20090915 */
  NDN_DTAG_Key = 27,
  NDN_DTAG_KeyLocator = 28,
  NDN_DTAG_KeyName = 29,
  NDN_DTAG_Length = 30,
  NDN_DTAG_Link = 31,
  NDN_DTAG_LinkAuthenticator = 32,
  NDN_DTAG_NameComponentCount = 33,	/* DeprecatedInInterest */
  NDN_DTAG_RootDigest = 36,
  NDN_DTAG_Signature = 37,
  NDN_DTAG_Start = 38,
  NDN_DTAG_Timestamp = 39,
  NDN_DTAG_Type = 40,
  NDN_DTAG_Nonce = 41,
  NDN_DTAG_Scope = 42,
  NDN_DTAG_Exclude = 43,
  NDN_DTAG_Bloom = 44,
  NDN_DTAG_BloomSeed = 45,
  NDN_DTAG_AnswerOriginKind = 47,
  NDN_DTAG_InterestLifetime = 48,
  NDN_DTAG_Witness = 53,
  NDN_DTAG_SignatureBits = 54,
  NDN_DTAG_DigestAlgorithm = 55,
  NDN_DTAG_BlockSize = 56,
  NDN_DTAG_FreshnessSeconds = 58,
  NDN_DTAG_FinalBlockID = 59,
  NDN_DTAG_PublisherPublicKeyDigest = 60,
  NDN_DTAG_PublisherCertificateDigest = 61,
  NDN_DTAG_PublisherIssuerKeyDigest = 62,
  NDN_DTAG_PublisherIssuerCertificateDigest = 63,
  NDN_DTAG_Data = 64,	/* 20090915 */
  NDN_DTAG_WrappedKey = 65,
  NDN_DTAG_WrappingKeyIdentifier = 66,
  NDN_DTAG_WrapAlgorithm = 67,
  NDN_DTAG_KeyAlgorithm = 68,
  NDN_DTAG_Label = 69,
  NDN_DTAG_EncryptedKey = 70,
  NDN_DTAG_EncryptedNonceKey = 71,
  NDN_DTAG_WrappingKeyName = 72,
  NDN_DTAG_Action = 73,
  NDN_DTAG_FaceID = 74,
  NDN_DTAG_IPProto = 75,
  NDN_DTAG_Host = 76,
  NDN_DTAG_Port = 77,
  NDN_DTAG_MulticastInterface = 78,
  NDN_DTAG_ForwardingFlags = 79,
  NDN_DTAG_FaceInstance = 80,
  NDN_DTAG_ForwardingEntry = 81,
  NDN_DTAG_MulticastTTL = 82,
  NDN_DTAG_MinSuffixComponents = 83,
  NDN_DTAG_MaxSuffixComponents = 84,
  NDN_DTAG_ChildSelector = 85,
  NDN_DTAG_RepositoryInfo = 86,
  NDN_DTAG_Version = 87,
  NDN_DTAG_RepositoryVersion = 88,
  NDN_DTAG_GlobalPrefix = 89,
  NDN_DTAG_LocalName = 90,
  NDN_DTAG_Policy = 91,
  NDN_DTAG_Namespace = 92,
  NDN_DTAG_GlobalPrefixName = 93,
  NDN_DTAG_PolicyVersion = 94,
  NDN_DTAG_KeyValueSet = 95,
  NDN_DTAG_KeyValuePair = 96,
  NDN_DTAG_IntegerValue = 97,
  NDN_DTAG_DecimalValue = 98,
  NDN_DTAG_StringValue = 99,
  NDN_DTAG_BinaryValue = 100,
  NDN_DTAG_NameValue = 101,
  NDN_DTAG_Entry = 102,
  NDN_DTAG_ACL = 103,
  NDN_DTAG_ParameterizedName = 104,
  NDN_DTAG_Prefix = 105,
  NDN_DTAG_Suffix = 106,
  NDN_DTAG_Root = 107,
  NDN_DTAG_ProfileName = 108,
  NDN_DTAG_Parameters = 109,
  NDN_DTAG_InfoString = 110,
  NDN_DTAG_StatusResponse = 112,
  NDN_DTAG_StatusCode = 113,
  NDN_DTAG_StatusText = 114,
  NDN_DTAG_SequenceNumber = 256,
  NDN_DTAG_NDNProtocolDataUnit = 17702112,

  NdnlpData = 20653248,
  NdnlpSequence = 20653249,
  NdnlpFlags = 20653250,
  NdnlpFragIndex = 20653251,
  NdnlpFragCount = 20653252,
  NdnlpPayload = 20653253,
  NdnlpAck = 20653254,
  NdnlpAckBlock = 20653255,
  NdnlpSequenceBase = 20653256,
  NdnlpBitmap = 20653257,

  DTAG_NdnldConnection = 20653264,
  DTAG_NdnldLowerProtocol = 20653265,
  DTAG_NdnldLocalInterface = 20653266,
  DTAG_NdnldSentPktsCapacity = 20653267,
  DTAG_NdnldRetransmitCount = 20653268,
  DTAG_NdnldRetransmitTime = 20653269,
  DTAG_NdnldAcknowledgeTime = 20653270
};


} // namespace NdnxParser
} // namespace ns3

#endif // _NDNB_PARSER_COMMON_H_
