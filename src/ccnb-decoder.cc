/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

#include "ccnb-decoder.h"
#include "print-helper.h"

#include <stdio.h>
#include <string.h>

extern "C"
{
#include <ccn/coding.h>
#include <ccn/extend_dict.h>
}
  
CcnbDecoder::CcnbDecoder (int formatting_flags, const struct ccn_dict *dtags)
{
  stringstack = ccn_charbuf_create ();
  if (stringstack == NULL) throw new DecoderException ();
  schema = CCN_NO_SCHEMA;
  tagdict = dtags->dict;
  tagdict_count = dtags->count;
  formatting_flags = formatting_flags;
  annotation = NULL;
}

CcnbDecoder::~CcnbDecoder ()
{
  if (callback != NULL ) callback(this, CALLBACK_FINAL, callbackdata);

  while (stack != NULL)
    {
      ccn_decoder_pop ();
    }
  
  ccn_charbuf_destroy (&stringstack);
}

void
CcnbDecoder::SetCallback (ccn_decoder_callback c, void *data)
{
  callback = c;
  if (c == NULL)
    {
      callbackdata = NULL;
    }
  else
    {
      callbackdata = data;
      c(this, CALLBACK_INITIAL, data);
    }
}

struct ccn_decoder_stack_item *
CcnbDecoder::ccn_decoder_push ()
{
  struct ccn_decoder_stack_item *s = new ccn_decoder_stack_item ();
  if (s != NULL)
    {
      s->link = stack;
      s->savedss = stringstack->length;
      s->saved_schema = schema;
      s->saved_schema_state = sstate;
      stack = s;
    }
  return(s);
}

void
CcnbDecoder::ccn_decoder_pop ()
{
  struct ccn_decoder_stack_item *s = stack;
  if (s != NULL)
    {
      stack = s->link;
      stringstack->length = s->savedss;
      schema = s->saved_schema;
      sstate = s->saved_schema_state;
      delete s;
    }
}

size_t
CcnbDecoder::Decode (const unsigned char *p, size_t n)
{
  int state = state;
  int tagstate = 0;
  size_t numval = numval;
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
              s = stack;
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
              else if (schema == -1-CCN_PROCESSING_INSTRUCTIONS)
                {
                  printf("?>");
                  if (sstate != 2)
                    {
                      state = -__LINE__;
                      break;
                    }
                }
              else {
                printf("</%s>", stringstack->buf + s->nameindex);
              }
              if (annotation != NULL)
                {
                  if (annotation->length > 0)
                    {
                      printf("<!--       ");
                      PrintHelper::print_percent_escaped(annotation->buf, annotation->length);
                      printf(" -->");
                    }
                  ccn_charbuf_destroy(&annotation);
                }
              ccn_decoder_pop();
              if (stack == NULL)
                {
                  if (callback != NULL)
                    callback(this, CALLBACK_OBJECTEND, callbackdata);
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
                  bignumval = numval;
                  i--;
                  continue;
                }
              numval = (numval << 7) + (c & 127);
              if (numval > (numval << (7-CCN_TT_BITS)))
                {
                  state = 9;
                  bignumval = numval;
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
              s->nameindex = stringstack->length;
              schema = -1-numval;
              sstate = 0;
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
              s->nameindex = stringstack->length;
              schema = numval;
              sstate = 0;
              tagname = NULL;
              if (numval <= INT_MAX)
                tagname = PrintHelper::dict_name_from_number(numval, tagdict, tagdict_count);
              if (tagname == NULL) {
                fprintf(stderr,
                        "*** Warning: unrecognized DTAG %lu\n",
                        (unsigned long)numval);
                ccn_charbuf_append(stringstack,
                                   "UNKNOWN_DTAG",
                                   sizeof("UNKNOWN_DTAG"));
                printf("<%s code=\"%lu\"",
                       stringstack->buf + s->nameindex,
                       (unsigned long)schema);
                schema = CCN_UNKNOWN_SCHEMA;
              }
              else {
                ccn_charbuf_append(stringstack, tagname, strlen(tagname)+1);
                printf("<%s", tagname);
              }
              if ((formatting_flags & VERBOSE_DECODE) != 0)
                {
                  if (annotation != NULL)
                    throw new DecoderException ();
                  if (numval == 15 /* Component */)
                    annotation = ccn_charbuf_create();
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
                  if ((formatting_flags & FORCE_BINARY) == 0 && PrintHelper::is_text_encodable(p, i, numval))
                    {
                      printf(" ccnbencoding=\"text\">");
                      state =  6;
                    }
                  else if ((formatting_flags & PREFER_HEX) != 0)
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
              base64_char_count = 0;
              break;
            case CCN_UDATA:
              if (tagstate == 1)
                {
                  tagstate = 0;
                  printf(">");
                }
              state = 3;
              if (schema == -1-CCN_PROCESSING_INSTRUCTIONS)
                {
                  if (sstate > 0)
                    {
                      printf(" ");
                    }
                  state = 6;
                  sstate += 1;
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
              ccn_charbuf_reserve(stringstack, 1);
              s->nameindex = stringstack->length;
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
              ccn_charbuf_reserve(stringstack, numval + 1);
              s->nameindex = stringstack->length;
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
              ccn_charbuf_reserve(stringstack, numval + 1);
              s->nameindex = stringstack->length;
              state = 4;
              break;
            default:
              state = -__LINE__;
            }
          }
          break;
        case 2: /* hex BLOB */
          c = p[i++];
          if (annotation != NULL)
            ccn_charbuf_append_value(annotation, c, 1);
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
          ccn_charbuf_append(stringstack, p + i, chunk);
          numval -= chunk;
          i += chunk;
          if (numval == 0)
            {
              ccn_charbuf_append(stringstack, (const unsigned char *)"\0", 1);
              s = stack;
              if (s == NULL ||
                  strlen((char*)stringstack->buf + s->nameindex) != 
                  stringstack->length -1 - s->nameindex)
                {
                  state = -__LINE__;
                  break;
                }
              if (state == 4)
                {
                  printf("<%s", stringstack->buf + s->nameindex);
                  tagstate = 1;
                }
              else
                {
                  printf(" %s=\"", stringstack->buf + s->nameindex);
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
              bignumval = (bignumval << 7) + (c & 127);
            }
          else {
            bignumval = (bignumval << (7-CCN_TT_BITS)) +
              ((c >> CCN_TT_BITS) & CCN_MAX_TINY);
            c &= CCN_TT_MASK;
            if (tagstate == 1)
              {
                tagstate = 0;
                printf(">");
              }
            /*
             * There's nothing that we actually need the bignumval
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
          if (annotation != NULL)
            ccn_charbuf_append_value(annotation, c, 1);
          printf("%c", PrintHelper::Base64[c >> 2]);
          base64_char_count++;
          if (--numval == 0)
            {
              printf("%c==", PrintHelper::Base64[(c & 3) << 4]);
              state = 0;
              base64_char_count += 3;
            }
          else
            {
              bits = (c & 3);
              state = 11;
            }
          if ((formatting_flags & FORCE_BINARY) == 0 && base64_char_count >= 64)
            {
              base64_char_count = 0;
              printf("\n");
            }
          break;
        case 11: /* base 64 BLOB - phase 1 */
          c = p[i++];
          if (annotation != NULL)
            ccn_charbuf_append_value(annotation, c, 1);
          printf("%c", PrintHelper::Base64[((bits & 3) << 4) + (c >> 4)]);
          base64_char_count++;
          if (--numval == 0)
            {
              printf("%c=", PrintHelper::Base64[(c & 0xF) << 2]);
              state = 0;
              base64_char_count += 2;
            }
          else
            {
              bits = (c & 0xF);
              state = 12;
            }
          if ((formatting_flags & FORCE_BINARY) == 0 && base64_char_count >= 64)
            {
              base64_char_count = 0;
              printf("\n");
            }
          break;
        case 12: /* base 64 BLOB - phase 2 */
          c = p[i++];
          if (annotation != NULL)
            ccn_charbuf_append_value(annotation, c, 1);
          printf("%c%c", PrintHelper::Base64[((bits & 0xF) << 2) + (c >> 6)],
                 PrintHelper::Base64[c & 0x3F]);
          base64_char_count += 2;
          if (--numval == 0)
            {
              state = 0;
            }
          else
            {
              state = 10;
            }
          if ((formatting_flags & FORCE_BINARY) == 0 && base64_char_count >= 64)
            {
              base64_char_count = 0;
              printf("\n");
            }
          break;
        default:
          n = i;
        }
    }
  state = state;
  tagstate = tagstate;
  numval = numval;
  return(i);
}
