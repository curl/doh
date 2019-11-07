/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/*
 * Issue a DNS-over-HTTPS name resolve call for A and/or AAAA.
 * Follow CNAMEs. Detect CNAME loops.
 * Collect responses and display them.
 * Timeout slow responses.
 *
 */

#ifdef _WIN32
#include <winsock2.h>
#endif

#if defined(_MSC_VER) && (_MSC_VER < 1800)
typedef enum {
  bool_false = 0,
  bool_true  = 1
} bool;
#define false bool_false
#define true  bool_true
#else
#include <stdbool.h>
#endif
enum iptrans { v4, v6, v46 };

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#ifndef _WIN32
#include <netinet/in.h>
#endif

#include "version.h"

#ifdef _WIN32
#define FMT_SIZE_T "Iu"
#else
#define FMT_SIZE_T "lu" /* actually a size_t */
#endif

#define DNS_CLASS_IN 0x01

#define DNS_TYPE_A     1
#define DNS_TYPE_NS    2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_TXT   16
#define DNS_TYPE_AAAA  28

#define MAX_ADDR 8
#define MAX_URLS 100

typedef enum {
  DOH_OK,
  DOH_DNS_BAD_LABEL,    /* 1 */
  DOH_DNS_OUT_OF_RANGE, /* 2 */
  DOH_DNS_CNAME_LOOP,   /* 3 */
  DOH_TOO_SMALL_BUFFER, /* 4 */
  DOH_OUT_OF_MEM,       /* 5 */
  DOH_DNS_RDATA_LEN,    /* 6 */
  DOH_DNS_MALFORMAT,    /* 7 - wrong size or bad ID */
  DOH_DNS_BAD_RCODE,    /* 8 - no such name */
  DOH_DNS_UNEXPECTED_TYPE,  /* 9 */
  DOH_DNS_UNEXPECTED_CLASS, /* 10 */
  DOH_NO_CONTENT            /* 11 */
} DOHcode;

struct data {
  char trace_ascii; /* 1 or 0 */
};

const char default_url[] = "https://dns.cloudflare.com/dns-query";

static
void dump(const char *text,
          FILE *stream, unsigned char *ptr, size_t size,
          char nohex)
{
  size_t i;
  size_t c;

  unsigned int width = 0x10;

  if(nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n",
          text, (long)size, (long)size);

  for(i = 0; i<size; i += width) {

    fprintf(stream, "%4.4lx: ", (long)i);

    if(!nohex) {
      /* hex not disabled, show it */
      for(c = 0; c < width; c++)
        if(i + c < size)
          fprintf(stream, "%02x ", ptr[i + c]);
        else
          fputs("   ", stream);
    }

    for(c = 0; (c < width) && (i + c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */
      if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
         ptr[i + c + 1] == 0x0A) {
        i += (c + 2 - width);
        break;
      }
      fprintf(stream, "%c",
              (ptr[i + c] >= 0x20) && (ptr[i + c]<0x80)?ptr[i + c]:'.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */
      if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stream); /* newline */
  }
  fflush(stream);
}

static
int my_trace(CURL *handle, curl_infotype type,
             char *data, size_t size,
             void *userp)
{
  struct data *config = (struct data *)userp;
  const char *text;
  (void)handle; /* prevent compiler warning */

  switch(type) {
  case CURLINFO_TEXT:
    fprintf(stderr, "== Info: %s", data);
    /* FALLTHROUGH */
  default: /* in case a new one is introduced to shock us */
    return 0;

  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case CURLINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  }

  dump(text, stderr, (unsigned char *)data, size, config->trace_ascii);
  return 0;
}

struct response {
  unsigned char *memory;
  size_t size;
};

struct addr6 {
  unsigned char byte[16];
};

struct cnamestore {
  size_t len;       /* length of cname */
  char *alloc;      /* allocated pointer */
  size_t allocsize; /* allocated size */
};

struct txtstore {
  int len;
  char txt[255];
};

struct dnsentry {
  unsigned int ttl;
  int numv4;
  unsigned int v4addr[MAX_ADDR];
  int numv6;
  struct addr6 v6addr[MAX_ADDR];
  int numcname;
  struct cnamestore cname[MAX_ADDR];
  int numtxt;
  struct txtstore txt[MAX_ADDR];
};

static const char *type2name(int dnstype)
{
  return (dnstype == 1)?"A":"AAAA";
}

static size_t
write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct response *mem = (struct response *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize);
  if(mem->memory == NULL) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;

  return realsize;
}

static size_t doh_encode(const char *host,
                         int dnstype,
                         unsigned char *dnsp, /* buffer */
                         size_t len) /* buffer size */
{
  size_t hostlen = strlen(host);
  unsigned char *orig = dnsp;
  const char *hostp = host;

  if(len < (12 + hostlen + 6))
    return DOH_TOO_SMALL_BUFFER;

  *dnsp++ = 0; /* 16 bit id */
  *dnsp++ = 0;
  *dnsp++ = 0x01; /* |QR|   Opcode  |AA|TC|RD| Set the RD bit */
  *dnsp++ = '\0'; /* |RA|   Z    |   RCODE   |                */
  *dnsp++ = '\0';
  *dnsp++ = 1;    /* QDCOUNT (number of entries in the question section) */
  *dnsp++ = '\0';
  *dnsp++ = '\0'; /* ANCOUNT */
  *dnsp++ = '\0';
  *dnsp++ = '\0'; /* NSCOUNT */
  *dnsp++ = '\0';
  *dnsp++ = '\0'; /* ARCOUNT */

  /* store a QNAME */
  do {
    char *dot = strchr(hostp, '.');
    size_t labellen;
    bool found = false;
    if(dot) {
      found = true;
      labellen = dot - hostp;
    }
    else
      labellen = strlen(hostp);
    if(labellen > 63)
      /* too long label, error out */
      return DOH_DNS_BAD_LABEL;
    *dnsp++ = (unsigned char)labellen;
    memcpy(dnsp, hostp, labellen);
    dnsp += labellen;
    hostp += labellen + 1;
    if(!found) {
      *dnsp++ = 0; /* terminating zero */
      break;
    }
  } while(1);

  *dnsp++ = '\0'; /* upper 8 bit TYPE */
  *dnsp++ = (unsigned char)dnstype;
  *dnsp++ = '\0'; /* upper 8 bit CLASS */
  *dnsp++ = DNS_CLASS_IN; /* IN - "the Internet" */

  return dnsp - orig;
}

static DOHcode skipqname(unsigned char *doh, size_t dohlen,
                         unsigned int *indexp)
{
  unsigned char length;
  do {
    if(dohlen < (*indexp + 1))
      return DOH_DNS_OUT_OF_RANGE;
    length = doh[*indexp];
    if((length & 0xc0) == 0xc0) {
      /* name pointer, advance over it and be done */
      if(dohlen < (*indexp + 2))
        return DOH_DNS_OUT_OF_RANGE;
      *indexp += 2;
      break;
    }
    if(length & 0xc0)
      return DOH_DNS_BAD_LABEL;
    if(dohlen < (*indexp + 1 + length))
      return DOH_DNS_OUT_OF_RANGE;
    *indexp += 1 + length;
  } while (length);
  return DOH_OK;
}

static unsigned short get16bit(unsigned char *doh, int index)
{
  return ((doh[index] << 8) | doh[index + 1]);
}

static unsigned int get32bit(unsigned char *doh, int index)
{
  return (doh[index] << 24) | (doh[index+1] << 16) |
    (doh[index+2] << 8) | doh[index+3];
}

static DOHcode store_a(unsigned char *doh,
                       int index,
                       struct dnsentry *d)
{
  /* this function silently ignore address over the limit */
  if(d->numv4 < MAX_ADDR) {
    unsigned int *inetp = &d->v4addr[d->numv4++];
    *inetp = get32bit(doh, index);
  }
  return DOH_OK;
}

static DOHcode store_aaaa(unsigned char *doh,
                          int index,
                          struct dnsentry *d)
{
  /* this function silently ignore address over the limit */
  if(d->numv6 < MAX_ADDR) {
    struct addr6 *inet6p = &d->v6addr[d->numv6++];
    memcpy(inet6p, &doh[index], 16);
  }
  return DOH_OK;
}

static DOHcode cnameappend(struct cnamestore *c,
                           unsigned char *src,
                           size_t len)
{
  if(!c->alloc) {
    c->allocsize = len + 1;
    c->alloc = malloc(c->allocsize);
    if(!c->alloc)
      return DOH_OUT_OF_MEM;
  }
  else if(c->allocsize < (c->allocsize + len + 1)) {
    char *ptr;
    c->allocsize += len + 1;
    ptr = realloc(c->alloc, c->allocsize);
    if(!ptr) {
      free(c->alloc);
      return DOH_OUT_OF_MEM;
    }
    c->alloc = ptr;
  }
  memcpy(&c->alloc[c->len], src, len);
  c->len += len;
  c->alloc[c->len]=0; /* keep it zero terminated */
  return DOH_OK;
}

static DOHcode store_cname(unsigned char *doh,
                           size_t dohlen,
                           unsigned int index,
                           struct dnsentry *d)
{
  struct cnamestore *c = &d->cname[d->numcname++];
  unsigned int loop = 128; /* a valid DNS name can never loop this much */
  unsigned char length;
  do {
    if(index >= dohlen)
      return DOH_DNS_OUT_OF_RANGE;
    length = doh[index];
    if((length & 0xc0) == 0xc0) {
      unsigned short newpos;
      /* name pointer, get the new offset (14 bits) */
      if((index + 1) >= dohlen)
        return DOH_DNS_OUT_OF_RANGE;

      /* move to the the new index */
      newpos = (length & 0x3f) << 8 | doh[index+1];
      index = newpos;
      continue;
    }
    else if(length & 0xc0)
      return DOH_DNS_BAD_LABEL; /* bad input */
    else
      index++;

    if(length) {
      DOHcode rc;
      if(c->len) {
        rc = cnameappend(c, (unsigned char *)".", 1);
        if(rc)
          return rc;
      }
      if((index + length) > dohlen)
        return DOH_DNS_BAD_LABEL;

      rc = cnameappend(c, &doh[index], length);
      if(rc)
        return rc;
      index += length;
    }
  } while (length && --loop);

  if(!loop)
    return DOH_DNS_CNAME_LOOP;
  return DOH_OK;
}

static DOHcode store_txt(unsigned char *doh,
                         size_t dohlen,
                         int rdlength,
                         unsigned int index,
                         struct dnsentry *d)
{
  if(d->numtxt < MAX_ADDR) {
    struct txtstore *t = &d->txt[d->numtxt++];
    unsigned char length = 0;

    if(index >= dohlen || (index + 1) >= dohlen)
      return DOH_DNS_OUT_OF_RANGE;

    length = doh[index++];
    if(length) {
      t->len = rdlength - 1;
      memcpy(t->txt, &doh[index], t->len);
      t->txt[t->len] = 0;
    }
  }

  return DOH_OK;
}

static DOHcode rdata(unsigned char *doh,
                     size_t dohlen,
                     unsigned short rdlength,
                     unsigned short type,
                     int index,
                     struct dnsentry *d)
{
  /* RDATA
     - A (TYPE 1):  4 bytes
     - AAAA (TYPE 28): 16 bytes
     - NS (TYPE 2): N bytes */
  DOHcode rc;

  switch(type) {
  case DNS_TYPE_A:
    if(rdlength != 4)
      return DOH_DNS_RDATA_LEN;
    rc = store_a(doh, index, d);
    if(rc)
      return rc;
    break;
  case DNS_TYPE_AAAA:
    if(rdlength != 16)
      return DOH_DNS_RDATA_LEN;
    rc = store_aaaa(doh, index, d);
    if(rc)
      return rc;
    break;
  case DNS_TYPE_CNAME:
    rc = store_cname(doh, dohlen, index, d);
    if(rc)
      return rc;
    break;
  case DNS_TYPE_TXT:
    if(rdlength <= 1)
      return DOH_DNS_RDATA_LEN;
    rc = store_txt(doh, dohlen, rdlength, index, d);
    if(rc)
      return rc;
    break;
  default:
    /* unsupported type, just skip it */
    break;
  }
  return DOH_OK;
}

static DOHcode doh_decode(unsigned char *doh,
                          size_t dohlen,
                          int dnstype,
                          struct dnsentry *d)
{
  unsigned char qr;
  unsigned char rcode;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short type=0;
  unsigned short class;
  unsigned short rdlength;
  unsigned short nscount;
  unsigned short arcount;
  unsigned int index = 12;
  DOHcode rc;

  qr = doh[2] & 0x80;
  if(dohlen < 12 || doh[0] || doh[1] || !qr)
    return DOH_DNS_MALFORMAT; /* too small or bad ID or not a response */
  rcode = doh[3] & 0x0f;
  if(rcode)
    return DOH_DNS_BAD_RCODE; /* bad rcode */

  qdcount = get16bit(doh, 4);
  while (qdcount) {
    rc = skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */
    if(dohlen < (index + 4))
      return DOH_DNS_OUT_OF_RANGE;
    index += 4; /* skip question's type and class */
    qdcount--;
  }

  ancount = get16bit(doh, 6);
  while (ancount) {
    unsigned int ttl;

    rc = skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    type = get16bit(doh, index);
    if((type != DNS_TYPE_CNAME) && (type != dnstype))
      /* Not the same type as was asked for nor CNAME */
      return DOH_DNS_UNEXPECTED_TYPE;
    index += 2;

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;
    class = get16bit(doh, index);
    if(DNS_CLASS_IN != class)
      return DOH_DNS_UNEXPECTED_CLASS; /* unsupported */
    index += 2;

    if(dohlen < (index + 4))
      return DOH_DNS_OUT_OF_RANGE;

    ttl = get32bit(doh, index);
    if(ttl < d->ttl)
      d->ttl = ttl;
    index += 4;

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    rdlength = get16bit(doh, index);
    index += 2;
    if(dohlen < (index + rdlength))
      return DOH_DNS_OUT_OF_RANGE;

    rc = rdata(doh, dohlen, rdlength, type, index, d);
    if(rc)
      return rc; /* bad rdata */
    index += rdlength;
    ancount--;
  }

  nscount = get16bit(doh, 8);
  while (nscount) {
    rc = skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */

    if(dohlen < (index + 8))
      return DOH_DNS_OUT_OF_RANGE;

    index += 2; /* type */
    index += 2; /* class */
    index += 4; /* ttl */

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    rdlength = get16bit(doh, index);
    index += 2;
    if(dohlen < (index + rdlength))
      return DOH_DNS_OUT_OF_RANGE;
    index += rdlength;
    nscount--;
  }

  arcount = get16bit(doh, 10);
  while (arcount) {
    rc = skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */

    if(dohlen < (index + 8))
      return DOH_DNS_OUT_OF_RANGE;

    index += 2; /* type */
    index += 2; /* class */
    index += 4; /* ttl */

    rdlength = get16bit(doh, index);
    index += 2;
    if(dohlen < (index + rdlength))
      return DOH_DNS_OUT_OF_RANGE;
    index += rdlength;
    arcount--;
  }

  if(index != dohlen)
    return DOH_DNS_MALFORMAT; /* something is wrong */

  if((type != DNS_TYPE_NS) && !d->numcname && !d->numv6 && !d->numv4 && !d->numtxt)
    /* nothing stored! */
    return DOH_NO_CONTENT;

  return DOH_OK; /* ok */
}

static void doh_init(struct dnsentry *d)
{
  memset(d, 0, sizeof(struct dnsentry));
  d->ttl = ~0u; /* default to max */
}

static void doh_cleanup(struct dnsentry *d)
{
  int i = 0;
  for(i=0; i< d->numcname; i++) {
    free(d->cname[i].alloc);
  }
}

/* one of these for each http request */
struct dnsprobe {
  CURL *curl;
  int dnstype;
  unsigned char dohbuffer[512];
  size_t dohlen;
  struct response serverdoh;
  struct data config;
};

static int initprobe(int dnstype, char *host, const char *url, CURLM *multi,
                     int trace_enabled, struct curl_slist *headers,
                     bool insecure_mode, enum iptrans transport,
                     struct curl_slist *resolve)
{
  CURL *curl;
  struct dnsprobe *p = calloc((size_t)1, sizeof *p);
  if(p == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    return 1;
  }
  p->dohlen = doh_encode(host, dnstype, p->dohbuffer, sizeof(p->dohbuffer));
  if(!p->dohlen) {
    fprintf(stderr, "Failed to encode DOH packet\n");
    return 2;
  }

  p->dnstype = dnstype;
  p->serverdoh.memory = malloc(1);  /* will be grown as needed by realloc above */
  p->serverdoh.size = 0;    /* no data at this point */
  p->config.trace_ascii = 0; /* enable ascii tracing */

  curl = curl_easy_init();
  if(curl) {
#ifdef _WIN32
    /* Search and set the CA certificate bundle in the path. */
    struct curl_tlssessioninfo *tls_backend_info = NULL;
    curl_easy_getinfo(curl, CURLINFO_TLS_SSL_PTR, &tls_backend_info);

    if(tls_backend_info->backend != CURLSSLBACKEND_SCHANNEL) {
      char *u = NULL;
      char buf[MAX_PATH] = { 0, };

      if(SearchPathA(NULL, "curl-ca-bundle.crt", NULL, sizeof buf, buf, &u)) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, buf);
        curl_easy_setopt(curl, CURLOPT_PROXY_CAINFO, buf);
      }
    }
#endif
    if(trace_enabled) {
      curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
      curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &p->config);
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }
    if(transport == v4)
      curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    else if(transport == v6)
      curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
    if(resolve != NULL)
      curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&p->serverdoh);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl-doh/1.0");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, p->dohbuffer);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, p->dohlen);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2);
    curl_easy_setopt(curl, CURLOPT_PRIVATE, p);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, insecure_mode?0L:1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, insecure_mode?0L:1L);

    p->curl = curl;

    /* add the individual transfers */
    curl_multi_add_handle(multi, curl);
  }
  else {
    fprintf(stderr, "curl_easy_init() failed\n");
    return 3;
  }

  return 0;
}

#ifdef _WIN32
#define WAITMS(x) Sleep(x)
#else
/* Portable sleep for platforms other than Windows. */
#define WAITMS(x)                               \
  struct timeval wait = { 0, (x) * 1000 };      \
  (void)select(0, NULL, NULL, NULL, &wait);
#endif

static void help(const char *msg)
{
  if(msg != NULL)
    fprintf(stderr, "%s:\n\n", msg);
  fprintf(stderr, "Usage: doh [options] <host> [URL]\n"
        "  -h  this help\n"
        "  -k  insecure mode - don't validate TLS certificate\n"
        "  -tTYPE (e.g., TXT, A, AAAA)\n"
        "      (to specify record type)\n"
        "  -T  test mode\n"
        "  -v  verbose mode\n"
        "  -4  use only IPv4 transport\n"
        "  -6  use only IPv6 transport\n"
        "  -rNAME:PORT:ADDRESS (e.g., example.com:443:127.0.0.1)\n"
        "      (to preload libcurl's DNS cache)\n"
        "  -V  show version\n"
        "(default URL is %s)\n",
        default_url);
  exit(1);
}

static void show_version(void)
{
  fputs("doh version " DOH_VERSION_TXT "\n", stdout);
  exit(0);
}

int main(int argc, char **argv)
{
  CURLMsg *msg;
  struct curl_slist *headers = NULL;
  struct curl_slist *resolve = NULL;
  enum iptrans transport = v46;
  int trace_enabled = 0;
  int test_mode = 0;
  int rc;
  const char *urls[MAX_URLS];
  int i, n_urls = 0;
  char *host;
  CURLM *multi;
  int still_running;
  int repeats = 0;
  struct dnsentry d;
  int successful = 0;
  int exit_status = 0;
  int queued;
  int query_type = 0; /* 0 default value outputs A, AAAA, CNAME */
  int paramlen;
  bool insecure_mode = false;

  for(argc--, argv++; argc > 0 && argv[0][0] == '-'; argc--, argv++) {
    switch(argv[0][1]) {
    case 'v': /* verbose */
      trace_enabled = 1;
      break;
    case 'V': /* version */
      show_version();
      break;
    case 't':
      paramlen = strlen(&argv[0][2]);
      if(strncmp(&argv[0][2], "AAAA", paramlen) == 0)
        query_type = DNS_TYPE_AAAA;
      else if(strncmp(&argv[0][2], "A", paramlen) == 0)
        query_type = DNS_TYPE_A;
      else if(strncmp(&argv[0][2], "CNAME", paramlen) == 0)
        query_type = DNS_TYPE_CNAME;
      else if(strncmp(&argv[0][2], "TXT", paramlen) == 0)
        query_type = DNS_TYPE_TXT;
      else
        help("type not supported");
      break;
    case 'T': /* test mode */
      test_mode = 1;
      break;
    case 'k': /* insecure */
      insecure_mode = true;
      break;
    case '4':
      transport = v4;
      break;
    case '6':
      transport = v6;
      break;
    case 'r':
      resolve = curl_slist_append(resolve, &argv[0][2]);
      break;
    case 'h': /* help */
      help(NULL);
      break;
    default:
      help("unrecognized option");
      break;
    }
  }
  if(argc < 1)
    help("no lookup name specified");
  argc--; host = *argv++;
  while(argc > 0) {
    if(n_urls == MAX_URLS)
      help("too many URLs");
    argc--; urls[n_urls++] = *argv++;
  }
  if(n_urls == 0)
    urls[n_urls++] = default_url;
  if(n_urls > 1 && !test_mode)
    help("multiple URLS only permitted in test mode");

  curl_global_init(CURL_GLOBAL_ALL);

  /* use the older content-type */
  headers = curl_slist_append(headers,
                              "Content-Type: application/dns-message");
  headers = curl_slist_append(headers,
                              "Accept: application/dns-message");

  /* init a multi stack */
  multi = curl_multi_init();

  doh_init(&d);

  for(i = 0; i < n_urls; i++) {
    if((transport == v4 || transport == v46) &&
        (query_type == 0 || query_type == DNS_TYPE_A)) {
      rc = initprobe(DNS_TYPE_A, host, urls[i], multi,
                     trace_enabled, headers, insecure_mode,
                     transport, resolve);
      if(rc != 0) {
        fprintf(stderr, "initprobe() failed (v4)\n");
        exit(1);
      }
    }
    if((transport == v6 || transport == v46) &&
        (query_type == 0 || query_type == DNS_TYPE_AAAA)) {
      rc = initprobe(DNS_TYPE_AAAA, host, urls[i], multi,
                     trace_enabled, headers, insecure_mode,
                     transport, resolve);
      if(rc != 0) {
        fprintf(stderr, "initprobe() failed (v6)\n");
        exit(1);
      }
    }

    if(query_type == DNS_TYPE_TXT) {
      rc = initprobe(DNS_TYPE_TXT, host, urls[i], multi,
                     trace_enabled, headers, insecure_mode,
                     transport, resolve);
      if(rc != 0) {
        fprintf(stderr, "initprobe() failed (v6)\n");
        exit(1);
      }
    }

    if(query_type == DNS_TYPE_CNAME) {
      rc = initprobe(DNS_TYPE_CNAME, host, urls[i], multi,
                     trace_enabled, headers, insecure_mode,
                     transport, resolve);
      if(rc != 0) {
        fprintf(stderr, "initprobe() failed (v6)\n");
        exit(1);
      }
    }
  }

  /* we start some action by calling perform right away */
  curl_multi_perform(multi, &still_running);

  exit_status = 0;
  do {
    CURLMcode mc; /* curl_multi_wait() return code */
    int numfds;

    /* wait for activity, timeout or "nothing" */
    mc = curl_multi_wait(multi, NULL, 0, 1000, &numfds);

    if(mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_wait() failed, code %d.\n", mc);
      break;
    }

    /* 'numfds' being zero means either a timeout or no file descriptors to
       wait for. Try timeout on first occurrence, then assume no file
       descriptors and no file descriptors to wait for means wait for 100
       milliseconds. */

    if(!numfds) {
      repeats++; /* count number of repeated zero numfds */
      if(repeats > 1) {
        WAITMS(10); /* sleep 10 milliseconds */
      }
    }
    else
      repeats = 0;

    curl_multi_perform(multi, &still_running);

    while((msg = curl_multi_info_read(multi, &queued))) {
      if(msg->msg == CURLMSG_DONE) {
        struct dnsprobe *probe;
        CURL *e = msg->easy_handle;
        curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &probe);

        /* Check for errors */
        if(msg->data.result != CURLE_OK) {
          fprintf(stderr, "probe for %s failed: %s\n",
                  type2name(probe->dnstype),
                  curl_easy_strerror(msg->data.result));
          exit_status = 1;
        }
        else {
          long response_code;
          curl_easy_getinfo(e, CURLINFO_RESPONSE_CODE, &response_code);
          if((response_code / 100 ) == 2) {
            rc = doh_decode(probe->serverdoh.memory,
                            probe->serverdoh.size,
                            probe->dnstype, &d);
            if(rc) {
              if(rc == DOH_DNS_BAD_RCODE) {
                fprintf(stderr, "Bad rcode, %s (%s)\n",
                        host, type2name(probe->dnstype));
              } else if(rc != DOH_NO_CONTENT) {
                fprintf(stderr, "problem %d decoding %" FMT_SIZE_T
                        " bytes response to probe for %s\n",
                        rc, probe->serverdoh.size, type2name(probe->dnstype));
                exit_status = 1;
              }
            }
            else
              successful++;
          }
          else {
            fprintf(stderr, "Probe for %s got response: %03ld\n",
                    type2name(probe->dnstype), response_code);
          }
          free(probe->serverdoh.memory);
        }
        curl_multi_remove_handle(multi, e);
        curl_easy_cleanup(e);
        free(probe);
      }
    }
  } while(still_running && (successful == 0 || test_mode == 0));

  if(successful && !test_mode) {
    int i;
    printf("[%s]\n", host);
    printf("TTL: %u seconds\n", d.ttl);
    for(i=0; i < d.numv4; i++) {
      printf("A: %d.%d.%d.%d\n",
             d.v4addr[i]>>24,
             (d.v4addr[i]>>16) & 0xff,
             (d.v4addr[i]>>8) & 0xff,
             d.v4addr[i] & 0xff);
    }
    for(i=0; i < d.numv6; i++) {
      int j;
      printf("AAAA: ");
      for(j=0; j<16; j+=2) {
        printf("%s%02x%02x", j ? ":" : "", d.v6addr[i].byte[j],
               d.v6addr[i].byte[j+1]);
      }
      printf("\n");
    }
    if(query_type == 0 || query_type == DNS_TYPE_CNAME)
      for(i=0; i < d.numcname; i++)
        printf("CNAME: %s\n", d.cname[i].alloc);
    for(i=0; i < d.numtxt; i++)
      printf("TXT: %s\n", d.txt[i].txt);
  }

  doh_cleanup(&d);
  if(headers != NULL)
    curl_slist_free_all(headers);
  if(resolve != NULL)
    curl_slist_free_all(resolve);
  curl_multi_cleanup(multi);

  /* we're done with libcurl, so clean it up */
  curl_global_cleanup();
  return exit_status;
}
