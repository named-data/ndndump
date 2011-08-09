/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#include "config.h"
#include "ccnb-print-xml.h"
#include "print-helper.h"

#include <stdio.h>
#include <string.h>

extern "C"
{
#include <ccn/coding.h>
#include <ccn/extend_dict.h>
}
  
CcnbDecoder::CcnbDecoder (int formatting_flags, const struct ccn_dict *dtags)
  : m_annotation( NULL )
  , m_state( 0 )
{
  m_stringstack = ccn_charbuf_create ();
  if (m_stringstack == NULL) throw new DecoderException ();
  m_schema = CCN_NO_SCHEMA;
  m_tagdict = dtags->dict;
  m_tagdict_count = dtags->count;
  m_formatting_flags = formatting_flags;
}

CcnbDecoder::~CcnbDecoder ()
{
  if (m_callback != NULL ) m_callback(this, CALLBACK_FINAL, m_callbackdata);

  while (m_stack != NULL)
    {
      ccn_decoder_pop ();
    }
  
  ccn_charbuf_destroy (&m_stringstack);
}

void
CcnbDecoder::SetCallback (ccn_decoder_callback c, void *data)
{
  m_callback = c;
  if (c == NULL)
    {
      m_callbackdata = NULL;
    }
  else
    {
      m_callbackdata = data;
      c (this, CALLBACK_INITIAL, m_callbackdata);
    }
}

struct ccn_decoder_stack_item *
CcnbDecoder::ccn_decoder_push ()
{
  struct ccn_decoder_stack_item *s = new ccn_decoder_stack_item ();
  if (s != NULL)
    {
      s->link = m_stack;
      s->savedss = m_stringstack->length;
      s->saved_schema = m_schema;
      s->saved_schema_state = m_sstate;
      m_stack = s;
    }
  return(s);
}

void
CcnbDecoder::ccn_decoder_pop ()
{
  struct ccn_decoder_stack_item *s = m_stack;
  if (s != NULL)
    {
      m_stack = s->link;
      m_stringstack->length = s->savedss;
      m_schema = s->saved_schema;
      m_sstate = s->saved_schema_state;
      delete s;
    }
}

size_t
CcnbDecoder::DecodeAndPrint (const unsigned char *p, size_t n)
{
  int state = m_state;
  int tagstate = 0;
  size_t numval = m_numval;
  size_t i = 0;
  unsigned char c;
  size_t chunk;
  struct ccn_decoder_stack_item *s;
  const char *tagname;
  while (i < n)
    {
      switch (state)
        {
        case 0: /* start new thing */
          if (tagstate > 1 && tagstate-- == 2)
            {
              printf("\""); /* close off the attribute value */
              ccn_decoder_pop();
            } 
          if (p[i] == CCN_CLOSE)
            {
              i++;
              s = m_stack;
              if (s == NULL || tagstate > 1)
                {
                  state = -__LINE__;
                  break;
                }
              if (tagstate == 1)
                {
                  tagstate = 0;
                  printf("/>");
                }
              else if (m_schema == -1-CCN_PROCESSING_INSTRUCTIONS)
                {
                  printf("?>");
                  if (m_sstate != 2)
                    {
                      state = -__LINE__;
                      break;
                    }
                }
              else {
                printf("</%s>", m_stringstack->buf + s->nameindex);
              }
              if (m_annotation != NULL)
                {
                  if (m_annotation->length > 0)
                    {
                      printf("<!--       ");
                      PrintHelper::print_percent_escaped(m_annotation->buf, m_annotation->length);
                      printf(" -->");
                    }
                  ccn_charbuf_destroy(&m_annotation);
                }
              ccn_decoder_pop();
              if (m_stack == NULL)
                {
                  if (m_callback != NULL)
                    m_callback(this, CALLBACK_OBJECTEND, m_callbackdata);
                  else
                    printf("\n");
                }
              break;
            }
          numval = 0;
          state = 1;
          /* FALLTHRU */
        case 1: /* parsing numval */
          c = p[i++];
          if ((c & CCN_TT_HBIT) == CCN_CLOSE)
            {
              if (numval > (numval << 7))
                {
                  state = 9;
                  m_bignumval = numval;
                  i--;
                  continue;
                }
              numval = (numval << 7) + (c & 127);
              if (numval > (numval << (7-CCN_TT_BITS)))
                {
                  state = 9;
                  m_bignumval = numval;
                }
            }
          else {
            numval = (numval << (7-CCN_TT_BITS)) +
              ((c >> CCN_TT_BITS) & CCN_MAX_TINY);
            c &= CCN_TT_MASK;
            switch (c) {
            case CCN_EXT:
              if (tagstate == 1)
                {
                  tagstate = 0;
                  printf(">");
                }
              s = ccn_decoder_push();
              s->nameindex = m_stringstack->length;
              m_schema = -1-numval;
              m_sstate = 0;
              switch (numval)
                {
                case CCN_PROCESSING_INSTRUCTIONS:
                  printf("<?");
                  break;
                default:
                  state = -__LINE__;
                }
              state = 0;
              break;
            case CCN_DTAG:
              if (tagstate == 1)
                {
                  tagstate = 0;
                  printf(">");
                }
              s = ccn_decoder_push();
              s->nameindex = m_stringstack->length;
              m_schema = numval;
              m_sstate = 0;
              tagname = NULL;
              if (numval <= INT_MAX)
                tagname = PrintHelper::dict_name_from_number(numval, m_tagdict, m_tagdict_count);
              if (tagname == NULL) {
                fprintf(stderr,
                        "*** Warning: unrecognized DTAG %lu\n",
                        (unsigned long)numval);
                ccn_charbuf_append(m_stringstack,
                                   "UNKNOWN_DTAG",
                                   sizeof("UNKNOWN_DTAG"));
                printf("<%s code=\"%lu\"",
                       m_stringstack->buf + s->nameindex,
                       (unsigned long)m_schema);
                m_schema = CCN_UNKNOWN_SCHEMA;
              }
              else {
                ccn_charbuf_append(m_stringstack, tagname, strlen(tagname)+1);
                printf("<%s", tagname);
              }
              if ((m_formatting_flags & VERBOSE_DECODE) != 0)
                {
                  if (m_annotation != NULL)
                    throw new DecoderException ();
                  if (numval == 15 /* Component */)
                    m_annotation = ccn_charbuf_create();
                }
              tagstate = 1;
              state = 0;
              break;
            case CCN_BLOB:
              if (numval > n - i)
                {
                  state = -__LINE__;
                  break;
                }                                                        
              if (tagstate == 1)
                {
                  tagstate = 0;
                  if ((m_formatting_flags & FORCE_BINARY) == 0 && PrintHelper::is_text_encodable(p, i, numval))
                    {
                      printf(" ccnbencoding=\"text\">");
                      state =  6;
                    }
                  else if ((m_formatting_flags & PREFER_HEX) != 0)
                    {
                      printf(" ccnbencoding=\"hexBinary\">");
                      state = 2;
                    }
                  else {
                    printf(" ccnbencoding=\"base64Binary\">");
                    state = 10;
                  }
                }
              else {
                fprintf(stderr, "blob not tagged in xml output\n");
                state = 10;
              }
              state = (numval == 0) ? 0 : state;
              m_base64_char_count = 0;
              break;
            case CCN_UDATA:
              if (tagstate == 1)
                {
                  tagstate = 0;
                  printf(">");
                }
              state = 3;
              if (m_schema == -1-CCN_PROCESSING_INSTRUCTIONS)
                {
                  if (m_sstate > 0)
                    {
                      printf(" ");
                    }
                  state = 6;
                  m_sstate += 1;
                }
              if (numval == 0)
                state = 0;
              break;
            case CCN_DATTR:
              if (tagstate != 1)
                {
                  state = -__LINE__;
                  break;
                }
              s = ccn_decoder_push();
              ccn_charbuf_reserve(m_stringstack, 1);
              s->nameindex = m_stringstack->length;
              printf(" UNKNOWN_DATTR_%lu=\"", (unsigned long)numval);
              tagstate = 3;
              state = 0;
              break;
            case CCN_ATTR:
              if (tagstate != 1)
                {
                  state = -__LINE__;
                  break;
                }
              if (numval >= n - i)
                {
                  state = -__LINE__;
                  break;
                }                            
              numval += 1; /* encoded as length-1 */
              s = ccn_decoder_push();
              ccn_charbuf_reserve(m_stringstack, numval + 1);
              s->nameindex = m_stringstack->length;
              state = 5;
              break;
            case CCN_TAG:
              if (tagstate == 1)
                {
                  tagstate = 0;
                  printf(">");
                }
              if (numval >= n - i)
                {
                  state = -__LINE__;
                  break;
                }                                                        
              numval += 1; /* encoded as length-1 */
              s = ccn_decoder_push ();
              ccn_charbuf_reserve(m_stringstack, numval + 1);
              s->nameindex = m_stringstack->length;
              state = 4;
              break;
            default:
              state = -__LINE__;
            }
          }
          break;
        case 2: /* hex BLOB */
          c = p[i++];
          if (m_annotation != NULL)
            ccn_charbuf_append_value(m_annotation, c, 1);
          printf("%02X", c);
          if (--numval == 0)
            {
              state = 0;
            }
          break;
        case 3: /* utf-8 data */
          c = p[i++];
          if (--numval == 0)
            {
              state = 0;
            }
          switch (c)
            {
            case 0:
              state = -__LINE__;
              break;
            case '&':
              printf("&amp;");
              break;
            case '<':
              printf("&lt;");
              break;
            case '>':
              printf("&gt;");
              break;
            case '"':
              printf("&quot;");
              break;
            default:
              printf("%c", c);
            }
          break;
        case 4: /* parsing tag name */
        case 5: /* parsing attribute name */
          chunk = n - i;
          if (chunk > numval)
            {
              chunk = numval;
            }
          if (chunk == 0)
            {
              state = -__LINE__;
              break;
            }
          ccn_charbuf_append(m_stringstack, p + i, chunk);
          numval -= chunk;
          i += chunk;
          if (numval == 0)
            {
              ccn_charbuf_append(m_stringstack, (const unsigned char *)"\0", 1);
              s = m_stack;
              if (s == NULL ||
                  strlen((char*)m_stringstack->buf + s->nameindex) != 
                  m_stringstack->length -1 - s->nameindex)
                {
                  state = -__LINE__;
                  break;
                }
              if (state == 4)
                {
                  printf("<%s", m_stringstack->buf + s->nameindex);
                  tagstate = 1;
                }
              else
                {
                  printf(" %s=\"", m_stringstack->buf + s->nameindex);
                  tagstate = 3;
                }
              state = 0;
            }
          break;
        case 6: /* processing instructions and text blobs */
          c = p[i++];
          if (--numval == 0)
            {
              state = 0;
            }
          printf("%c", c);
          break;
        case 9: /* parsing big numval - cannot be a length anymore */
          c = p[i++];
          if ((c & CCN_TT_HBIT) == CCN_CLOSE)
            {
              m_bignumval = (m_bignumval << 7) + (c & 127);
            }
          else {
            m_bignumval = (m_bignumval << (7-CCN_TT_BITS)) +
              ((c >> CCN_TT_BITS) & CCN_MAX_TINY);
            c &= CCN_TT_MASK;
            if (tagstate == 1)
              {
                tagstate = 0;
                printf(">");
              }
            /*
             * There's nothing that we actually need the m_bignumval
             * for, so we can probably GC this whole state and
             * give up earlier.
             */
            switch (c)
              {
              default:
                state = -__LINE__;
              }
          }
          break;
        case 10: /* base 64 BLOB - phase 0 */
          c = p[i++];
          if (m_annotation != NULL)
            ccn_charbuf_append_value(m_annotation, c, 1);
          printf("%c", PrintHelper::Base64[c >> 2]);
          m_base64_char_count++;
          if (--numval == 0)
            {
              printf("%c==", PrintHelper::Base64[(c & 3) << 4]);
              state = 0;
              m_base64_char_count += 3;
            }
          else
            {
              m_bits = (c & 3);
              state = 11;
            }
          if ((m_formatting_flags & FORCE_BINARY) == 0 && m_base64_char_count >= 64)
            {
              m_base64_char_count = 0;
              printf("\n");
            }
          break;
        case 11: /* base 64 BLOB - phase 1 */
          c = p[i++];
          if (m_annotation != NULL)
            ccn_charbuf_append_value(m_annotation, c, 1);
          printf("%c", PrintHelper::Base64[((m_bits & 3) << 4) + (c >> 4)]);
          m_base64_char_count++;
          if (--numval == 0)
            {
              printf("%c=", PrintHelper::Base64[(c & 0xF) << 2]);
              state = 0;
              m_base64_char_count += 2;
            }
          else
            {
              m_bits = (c & 0xF);
              state = 12;
            }
          if ((m_formatting_flags & FORCE_BINARY) == 0 && m_base64_char_count >= 64)
            {
              m_base64_char_count = 0;
              printf("\n");
            }
          break;
        case 12: /* base 64 BLOB - phase 2 */
          c = p[i++];
          if (m_annotation != NULL)
            ccn_charbuf_append_value(m_annotation, c, 1);
          printf("%c%c", PrintHelper::Base64[((m_bits & 0xF) << 2) + (c >> 6)],
                 PrintHelper::Base64[c & 0x3F]);
          m_base64_char_count += 2;
          if (--numval == 0)
            {
              state = 0;
            }
          else
            {
              state = 10;
            }
          if ((m_formatting_flags & FORCE_BINARY) == 0 && m_base64_char_count >= 64)
            {
              m_base64_char_count = 0;
              printf("\n");
            }
          break;
        default:
          n = i;
        }
    }
  m_state = state;
  m_tagstate = tagstate;
  m_numval = numval;
  return(i);
}
