
struct ndn_dict_entry {
    int index;              /**< matches enum ndn_dtag above */
    const char *name;       /**< textual name of dtag */
};

struct ndn_dict {
    int count;              /**< Count of elements in the table */
    const struct ndn_dict_entry *dict; /**< the table entries */
};

/**
 * Type tag for a ndnb start marker.
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

/** NDN_CLOSE terminates composites */
#define NDN_CLOSE ((unsigned char)(0))

enum ndn_ext_subtype {
    /* skip smallest values for now */
    NDN_PROCESSING_INSTRUCTIONS = 16 /* <?name:U value:U?> */
};

/**
 * DTAG identifies ndnb-encoded elements.
 * c.f. tagname.csvdict
 * See the gen_enum_dtag script for help updating these.
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
    NDN_DTAG_ExtOpt = 34,
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
    NDN_DTAG_ContentObject = 64,	/* 20090915 */
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
    NDN_DTAG_SyncNode = 115,
    NDN_DTAG_SyncNodeKind = 116,
    NDN_DTAG_SyncNodeElement = 117,
    NDN_DTAG_SyncVersion = 118,
    NDN_DTAG_SyncNodeElements = 119,
    NDN_DTAG_SyncContentHash = 120,
    NDN_DTAG_SyncLeafCount = 121,
    NDN_DTAG_SyncTreeDepth = 122,
    NDN_DTAG_SyncByteCount = 123,
    NDN_DTAG_SyncConfigSlice = 124,
    NDN_DTAG_SyncConfigSliceList = 125,
    NDN_DTAG_SyncConfigSliceOp = 126,
    NDN_DTAG_SyncNodeDeltas = 127,
    NDN_DTAG_SequenceNumber = 256,
    NDN_DTAG_NDNProtocolDataUnit = 17702112
};

#include "ns3/ndnb-parser-dtag.h"

#define ARRAY_N(arr) (sizeof(arr)/sizeof(arr[0]))
/**
 * See the gen_dtag_table script for help updating these.
 */
static const struct ndn_dict_entry ndn_tagdict[] = {
    {NDN_DTAG_Any, "Any"},
    {NDN_DTAG_Name, "Name"},
    {NDN_DTAG_Component, "Component"},
    {NDN_DTAG_Certificate, "Certificate"},
    {NDN_DTAG_Collection, "Collection"},
    {NDN_DTAG_CompleteName, "CompleteName"},
    {NDN_DTAG_Content, "Content"},
    {NDN_DTAG_SignedInfo, "SignedInfo"},
    {NDN_DTAG_ContentDigest, "ContentDigest"},
    {NDN_DTAG_ContentHash, "ContentHash"},
    {NDN_DTAG_Count, "Count"},
    {NDN_DTAG_Header, "Header"},
    {NDN_DTAG_Interest, "Interest"},
    {NDN_DTAG_Key, "Key"},
    {NDN_DTAG_KeyLocator, "KeyLocator"},
    {NDN_DTAG_KeyName, "KeyName"},
    {NDN_DTAG_Length, "Length"},
    {NDN_DTAG_Link, "Link"},
    {NDN_DTAG_LinkAuthenticator, "LinkAuthenticator"},
    {NDN_DTAG_NameComponentCount, "NameComponentCount"},
    {NDN_DTAG_ExtOpt, "ExtOpt"},
    {NDN_DTAG_RootDigest, "RootDigest"},
    {NDN_DTAG_Signature, "Signature"},
    {NDN_DTAG_Start, "Start"},
    {NDN_DTAG_Timestamp, "Timestamp"},
    {NDN_DTAG_Type, "Type"},
    {NDN_DTAG_Nonce, "Nonce"},
    {NDN_DTAG_Scope, "Scope"},
    {NDN_DTAG_Exclude, "Exclude"},
    {NDN_DTAG_Bloom, "Bloom"},
    {NDN_DTAG_BloomSeed, "BloomSeed"},
    {NDN_DTAG_AnswerOriginKind, "AnswerOriginKind"},
    {NDN_DTAG_InterestLifetime, "InterestLifetime"},
    {NDN_DTAG_Witness, "Witness"},
    {NDN_DTAG_SignatureBits, "SignatureBits"},
    {NDN_DTAG_DigestAlgorithm, "DigestAlgorithm"},
    {NDN_DTAG_BlockSize, "BlockSize"},
    {NDN_DTAG_FreshnessSeconds, "FreshnessSeconds"},
    {NDN_DTAG_FinalBlockID, "FinalBlockID"},
    {NDN_DTAG_PublisherPublicKeyDigest, "PublisherPublicKeyDigest"},
    {NDN_DTAG_PublisherCertificateDigest, "PublisherCertificateDigest"},
    {NDN_DTAG_PublisherIssuerKeyDigest, "PublisherIssuerKeyDigest"},
    {NDN_DTAG_PublisherIssuerCertificateDigest, "PublisherIssuerCertificateDigest"},
    {NDN_DTAG_ContentObject, "ContentObject"},
    {NDN_DTAG_WrappedKey, "WrappedKey"},
    {NDN_DTAG_WrappingKeyIdentifier, "WrappingKeyIdentifier"},
    {NDN_DTAG_WrapAlgorithm, "WrapAlgorithm"},
    {NDN_DTAG_KeyAlgorithm, "KeyAlgorithm"},
    {NDN_DTAG_Label, "Label"},
    {NDN_DTAG_EncryptedKey, "EncryptedKey"},
    {NDN_DTAG_EncryptedNonceKey, "EncryptedNonceKey"},
    {NDN_DTAG_WrappingKeyName, "WrappingKeyName"},
    {NDN_DTAG_Action, "Action"},
    {NDN_DTAG_FaceID, "FaceID"},
    {NDN_DTAG_IPProto, "IPProto"},
    {NDN_DTAG_Host, "Host"},
    {NDN_DTAG_Port, "Port"},
    {NDN_DTAG_MulticastInterface, "MulticastInterface"},
    {NDN_DTAG_ForwardingFlags, "ForwardingFlags"},
    {NDN_DTAG_FaceInstance, "FaceInstance"},
    {NDN_DTAG_ForwardingEntry, "ForwardingEntry"},
    {NDN_DTAG_MulticastTTL, "MulticastTTL"},
    {NDN_DTAG_MinSuffixComponents, "MinSuffixComponents"},
    {NDN_DTAG_MaxSuffixComponents, "MaxSuffixComponents"},
    {NDN_DTAG_ChildSelector, "ChildSelector"},
    {NDN_DTAG_RepositoryInfo, "RepositoryInfo"},
    {NDN_DTAG_Version, "Version"},
    {NDN_DTAG_RepositoryVersion, "RepositoryVersion"},
    {NDN_DTAG_GlobalPrefix, "GlobalPrefix"},
    {NDN_DTAG_LocalName, "LocalName"},
    {NDN_DTAG_Policy, "Policy"},
    {NDN_DTAG_Namespace, "Namespace"},
    {NDN_DTAG_GlobalPrefixName, "GlobalPrefixName"},
    {NDN_DTAG_PolicyVersion, "PolicyVersion"},
    {NDN_DTAG_KeyValueSet, "KeyValueSet"},
    {NDN_DTAG_KeyValuePair, "KeyValuePair"},
    {NDN_DTAG_IntegerValue, "IntegerValue"},
    {NDN_DTAG_DecimalValue, "DecimalValue"},
    {NDN_DTAG_StringValue, "StringValue"},
    {NDN_DTAG_BinaryValue, "BinaryValue"},
    {NDN_DTAG_NameValue, "NameValue"},
    {NDN_DTAG_Entry, "Entry"},
    {NDN_DTAG_ACL, "ACL"},
    {NDN_DTAG_ParameterizedName, "ParameterizedName"},
    {NDN_DTAG_Prefix, "Prefix"},
    {NDN_DTAG_Suffix, "Suffix"},
    {NDN_DTAG_Root, "Root"},
    {NDN_DTAG_ProfileName, "ProfileName"},
    {NDN_DTAG_Parameters, "Parameters"},
    {NDN_DTAG_InfoString, "InfoString"},
    {NDN_DTAG_StatusResponse, "StatusResponse"},
    {NDN_DTAG_StatusCode, "StatusCode"},
    {NDN_DTAG_StatusText, "StatusText"},
    {NDN_DTAG_SyncNode, "SyncNode"},
    {NDN_DTAG_SyncNodeKind, "SyncNodeKind"},
    {NDN_DTAG_SyncNodeElement, "SyncNodeElement"},
    {NDN_DTAG_SyncVersion, "SyncVersion"},
    {NDN_DTAG_SyncNodeElements, "SyncNodeElements"},
    {NDN_DTAG_SyncContentHash, "SyncContentHash"},
    {NDN_DTAG_SyncLeafCount, "SyncLeafCount"},
    {NDN_DTAG_SyncTreeDepth, "SyncTreeDepth"},
    {NDN_DTAG_SyncByteCount, "SyncByteCount"},
    {NDN_DTAG_SyncConfigSlice, "SyncConfigSlice"},
    {NDN_DTAG_SyncConfigSliceList, "SyncConfigSliceList"},
    {NDN_DTAG_SyncConfigSliceOp, "SyncConfigSliceOp"},
    {NDN_DTAG_SyncNodeDeltas, "SyncNodeDeltas"},
    {NDN_DTAG_SequenceNumber, "SequenceNumber"},
    {NDN_DTAG_NDNProtocolDataUnit, "NDNProtocolDataUnit"},

    {ns3::NdnbParser::DTAG_NdnldConnection, "NdnldConnection"},
    {ns3::NdnbParser::DTAG_NdnldLowerProtocol, "NdnldLowerProtocol"},
    {ns3::NdnbParser::DTAG_NdnldLocalInterface, "NdnldLocalInterface"},
    {ns3::NdnbParser::DTAG_NdnldSentPktsCapacity, "NdnldSentPktsCapacity"},
    {ns3::NdnbParser::DTAG_NdnldRetransmitCount, "NdnldRetransmitCount"},
    {ns3::NdnbParser::DTAG_NdnldRetransmitTime, "NdnldRetransmitCount"},
    {ns3::NdnbParser::DTAG_NdnldAcknowledgeTime, "NdnldRetransmitCount"},

    {ns3::NdnbParser::NdnlpData, "NdnlpData"},
    {ns3::NdnbParser::NdnlpSequence, "NdnlpSequence"},
    {ns3::NdnbParser::NdnlpFlags, "NdnlpFlags"},
    {ns3::NdnbParser::NdnlpFragIndex, "NdnlpFragIndex"},
    {ns3::NdnbParser::NdnlpFragCount, "NdnlpFragCount"},
    {ns3::NdnbParser::NdnlpPayload, "NdnlpPayload"},
    {ns3::NdnbParser::NdnlpAck, "NdnlpAck"},
    {ns3::NdnbParser::NdnlpAckBlock, "NdnlpAckBlock"},
    {ns3::NdnbParser::NdnlpSequenceBase, "NdnlpSequenceBase"},
    {ns3::NdnbParser::NdnlpBitmap, "NdnlpBitmap"},

    {0, 0}
};

struct ndn_dict ndn_dtag_dict2 = {ARRAY_N(ndn_tagdict) - 1, ndn_tagdict};
