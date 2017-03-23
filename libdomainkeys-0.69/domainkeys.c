#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
// added by nhatier for compilation under MSVC
#ifdef _MSC_VER
#include <string.h>
  #define strncasecmp strnicmp
  #define strcasecmp stricmp
  #define snprintf _snprintf
#else
  #ifndef _STRINGS_H
    #include <strings.h>
  #endif
  #ifndef _STRING_H
    #include <string.h>
  #endif
#endif
// end added by nhatier
extern char *dns_text(char *);

/* STARTHEAD */
/* This is libdomainkeys.  It's Copyright (c) 2004 Yahoo, Inc.
 * This code incorporates intellectual property owned by
 * Yahoo! and licensed pursuant to the Yahoo! DomainKeys Public License
 * Agreement: http://domainkeys.sourceforge.net/license/softwarelicense1-0.html
 */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#ifdef SWIG
%module domainkeys
%{
#include "domainkeys.h"
%}
#endif

#include "dktrace.h"

/* Performance/Debug options.
 * Uncomment below or use -D switch in gcc
 * DK_DEBUG Dumps whatever dkhash() hashes in to stderr and turns on
 *  some debug warnings that should never happen
 * DK_HASH_BUFF Enables code that uses a buffer when processing the
 *  canocalized message, reducing calls to the crypto library (from dkhash()),
 *  but can use up slightly more memory
*/
//#define DK_DEBUG 1
#define DK_HASH_BUFF 1


#define DKMARK ('D' | 'K'<<8 | 'E'<<16 | 'Y'<<24)
#define DK_SIGNING_SIGN 0
#define DK_SIGNING_VERIFY 1
#define DK_SIGNING_NOSIGN 2
#define DK_SIGNING_NOVERIFY 3
#define DK_MALLOC(s)  OPENSSL_malloc(s)
#define DK_MFREE(s)   OPENSSL_free(s); s = NULL;
#define DKERR(x) ((dk->errline=__LINE__),(dk->errfile=__FILE__),(x))
#define DK_BLOCK 1024 //default size of malloc'd block

/*
 * Option Flags for dk_setopts
 * OR together or run dk_setopts several times
 * All option flags are OFF by default
*/
#define DKOPT_TRACE_h 0x01 //enables tracking character count in pre-canon header
#define DKOPT_TRACE_H 0x02 //enables tracking character count in post-canon header
#define DKOPT_TRACE_b 0x04 //enables tracking character count in pre-canon body
#define DKOPT_TRACE_B 0x08 //enables tracking character count in post-canon header
#define DKOPT_RDUPE 0x10 //enables skipping duplicate headers when generateing a signature

typedef enum
{
  DK_STAT_OK, /* Function completed successfully */
  DK_STAT_BADSIG, /* Signature was available but failed to verify against domain specified key */
  DK_STAT_NOSIG, /* No signature available in message */
  DK_STAT_NOKEY, /* No public key available (permanent failure) */
  DK_STAT_BADKEY, /* Unusable key, public if verifying, private if signing */
  DK_STAT_CANTVRFY, /* Cannot get domain key to verify signature (temporary failure) */
  DK_STAT_SYNTAX, /* Message is not valid syntax. Signature could not be created/checked */
  DK_STAT_NORESOURCE, /* Could not get critical resource (temporary failure) */
  DK_STAT_ARGS, /* Arguments are not usable. */
  DK_STAT_REVOKED,    /* Key has been revoked. */
  DK_STAT_INTERNAL, /* cannot call this routine in this context.  Internal error. */
  DK_STAT_GRANULARITY, /* Granularity mismatch: sender doesn't match g= option. */
} DK_STAT;

typedef enum
{
  DK_FLAG_TESTING = 1,    /* set when in testing mode. */
  DK_FLAG_SIGNSALL = 2,   /* domain signs all outgoing email. */
  DK_FLAG_SET = 4,    /* flags set from a successful DNS query */
  DK_FLAG_G = 8,    /* g tag was present in the selector. */
} DK_FLAGS;
typedef enum
{
  DK_TXT_KEY = 0,
  DK_TXT_POLICY
} DK_TXT;

typedef enum
{
  DK_CANON_SIMPLE = 0,
  DK_CANON_NOFWS = 1,
} DK_CANON;
/* STARTSTRUCT */
typedef struct
{
/* STARTPRIV */
  const EVP_MD *md;
/* STOPPRIV */

} DK_LIB;
/* STOPSTRUCT */

//UnixWare Fix -Tim
/* STARTSTRUCT */
typedef struct
{
/* STARTPRIV */
  int dkmarker;     /* in case somebody casts in */
  EVP_MD_CTX mdctx;   /* the hash */
  int signing;      /* our current signing/verifying state */
  int in_headers;   /* true if we're still processing headers */
  char *header;     /* points to a malloc'ed block for header. */
  int headerlen;    /* total length of the header. */
  int headermax;    /* length of malloc'ed block */
  int headerlinelen;    /* current column of the header */
  int start_signed;   /* offset into header of the start of the headers. */
  char *from;     /* saved copy of From: header */
  char *sender;     /* saved copy of Sender: header */
  char *dksign;     /* saved copy of DK-Sig: header */
  char *dktrace;  /* saved copy of DK-Trace: header */
  char *domain;     /* d= */
  char *selector;   /* s= */
  char *signature;    /* b= */
  char *granularity;    /* g= */
  char *keyrec; /* caller supplied TXT key record */
  char *policyrec; /* caller supplied TXT policy record */
  int canon;      /* c= canonicalization being applied. */
  int state;      /* state variable for canonicalization */
  char *headers;    /* h= */
  int errline;      /* source line of most recent error */
  char *errfile;    /* source file of most recent error */
  char *sender_beforesign; /* saved copy of Sender: header */
  int opts;  /* trace and rdupe flags */
  char last_char; /* the last character processed by dk_message() */
#ifdef DK_HASH_BUFF
  char *hash_buff; /* buffer for hashing */
  int hash_buff_len; /* length of hashing buffer */
#endif
  DK_TRACE *trace; /* pointer to trace count table */
  DK_TRACE *traceheader; /* pointer to trace count table from DK-Trace:*/
/* STOPPRIV */
} DK;
/* STOPSTRUCT */


/* STARTPRIV */
static char *errors[] =
{
  "DK_STAT_OK: Function completed successfully",
  "DK_STAT_BADSIG: Signature was available but failed to verify against domain specified key",
  "DK_STAT_NOSIG: No signature available in message",
  "DK_STAT_NOKEY: No public key available (permanent failure)",
  "DK_STAT_BADKEY: Unusable key, public if verifying, private if signing.",
  "DK_STAT_CANTVRFY: Cannot get domain key to verify signature (temporary failure)",
  "DK_STAT_SYNTAX: Message is not valid syntax. Signature could not be created/checked",
  "DK_STAT_NORESOURCE: Could not get critical resource (temporary failure)",
  "DK_STAT_ARGS: Arguments are not usable.",
  "DK_STAT_REVOKED: Key has been revoked.",
  "DK_STAT_INTERNAL: cannot call this routine in this context.  Internal error.",
  "DK_STAT_GRANULARITY: Granularity mismatch: sender doesn't match g= option."
};
/* STOPPRIV */
/* STOPHEAD */
//prototype for dk_from
char* dk_from(DK *);
int dk_headers(DK *, char *);

char* dk_strdup(const char* s)
{
  char* new = DK_MALLOC(strlen(s)+1);
  if (new != 0)
  {
    strcpy(new, s);
  }
  return new;
}

/* HEADER */
/* returns the source file from which an error was returned. */
char * dk_errfile(DK *dk)
{
  return dk->errfile;
}

/* HEADER */
/* returns the source line number from which an error was returned. */
int dk_errline(DK *dk)
{
  return dk->errline;
}

/* HEADER */
/* Per-process, one-time initialization
 * Returns library structure for subsequent dk_sign or dk_verify calls.
 * Consult statp before using.
 *
 * When terminating the PROCESS its a good idea to call dk_shutdown()
 * When terminating a THREAD it's a good idea to call ERR_remove_state(0); defined in <openssl/err.h>
 * NOTE: DK_LIB pointers are safe to use over multiple threads
 *       DK pointers are NOT safe to use over multiple threads
 */
DK_LIB *dk_init(DK_STAT *statp)
{
  DK_LIB *dklib;

  dklib = DK_MALLOC(sizeof(DK_LIB));
  if (!dklib)
  {
    if (statp)
    {
      *statp = DK_STAT_NORESOURCE;
    }
    return NULL;
  }
  dklib->md = EVP_sha1();
  if (!dklib->md)
  {
    if (statp)
    {
      *statp = DK_STAT_INTERNAL;
    }
    DK_MFREE(dklib);
    return NULL;
  }
  if (statp)
  {
    *statp = DK_STAT_OK;
  }
  return dklib;
}

/* HEADER */
/* Per-process, one-time cleanup
 * Should be called just before the application ends.
 * the dklib pointer is not valid anymore after this call
 * This function should be called even if dk_init failed.
 * It's safe to call dk_shutdown with a NULL pointer
 */
void dk_shutdown(DK_LIB * dklib)
{
   if (dklib)
   {
      DK_MFREE(dklib);
   }
   CRYPTO_cleanup_all_ex_data();
}

/* start a new header */
static DK_STAT dkinit_new_header(DK *dk)
{
  dk->headermax = DK_BLOCK;
  dk->header = DK_MALLOC(DK_BLOCK);
  if (!dk->header)
  {
    return DKERR(DK_STAT_NORESOURCE);
  }
  memset(dk->header,0,DK_BLOCK);
  dk->headerlen = 0;
  dk->headerlinelen = 1;  /* always store the first char. */
  dk->in_headers = 1;
  dk->start_signed = 0;
  dk->from = NULL;
  dk->sender = NULL;
  dk->dksign = NULL;
  dk->dktrace = NULL;
  dk->domain = NULL;
  dk->selector = NULL;
  dk->signature = NULL;
  dk->canon = DK_CANON_SIMPLE;
  dk->state = 0;
  dk->headers = 0;
  dk->sender_beforesign = NULL;
  dk->opts = 0;
  dk->last_char = '\0';
  dk->trace = NULL;
  dk->traceheader = NULL;
  dk->granularity = NULL;
  dk->keyrec = NULL;
  dk->policyrec = NULL;
#ifdef DK_HASH_BUFF
  dk->hash_buff = DK_MALLOC(DK_BLOCK);
  if (!dk->hash_buff)
  {
    return DKERR(DK_STAT_NORESOURCE);
  }
  memset(dk->hash_buff,0,DK_BLOCK);
  dk->hash_buff_len = 0;
#endif
  return DKERR(DK_STAT_OK);
}

/* HEADER */
/* Set dk options, use instead of dk_remdupe and dk_enable_trace
 * Can be called multiple times.
 * use after dk_sign()/dk_verify()
 *
 * the bits field can be an OR of any of the following
 *DKOPT_TRACE_h Trace pre-canon header
 *DKOPT_TRACE_H Trace post-canon header
 *DKOPT_TRACE_b Trace pre-canon body
 *DKOPT_TRACE_B Trace post-canon body
 *DKOPT_RDUPE   Exclude duplicate headers from hash (Signing only)
 */
DK_STAT dk_setopts(DK *dk, int bits)
{
  if (!dk)
    return DK_STAT_ARGS;
  if ((dk->headerlen == 0)&&((dk->signing == DK_SIGNING_NOVERIFY)||(dk->signing == DK_SIGNING_SIGN)))
  {
    dk->opts |= bits;
    if ((bits & (DKOPT_TRACE_h|DKOPT_TRACE_H|DKOPT_TRACE_b|DKOPT_TRACE_B)) && !dk->trace)
    {
      dk->trace = DK_MALLOC(sizeof(DK_TRACE));
      if (!dk->trace)
        return DKERR(DK_STAT_NORESOURCE);
      dkt_init(dk->trace);
    }
    if ((dk->signing != DK_SIGNING_SIGN) && (bits & DKOPT_RDUPE))
    {
      return DKERR(DK_STAT_INTERNAL); //cant do rdupe in verify mode
    }
    return DKERR(DK_STAT_OK);
  }
  return DKERR(DK_STAT_INTERNAL);
}
/* HEADER */
/* returns the int holding the options set
 * See dk_setopts for bit flags
 */
int dk_getopts(DK *dk)
{
  if (!dk)
    return 0;
  return (dk->opts);
}

/* HEADER */
/* DEPRECATED in favor of calling dk_setopts().
 * Enables character trace tracking
 *
 * use after dk_sign()/dk_verify()
 */
DK_STAT dk_enable_trace(DK *dk)
{
  return dk_setopts(dk,(DKOPT_TRACE_h|DKOPT_TRACE_H|DKOPT_TRACE_b|DKOPT_TRACE_B));
}
/* HEADER */
/* Prints trace table to *store variable (char string)
 * *dk is the container for the table
 * *store is a pointer to a character array to output to
 * store_size is the size of the character array *store
 *
 */
DK_STAT dk_get_trace(DK *dk, DK_TRACE_TYPE type, char *store, int store_size)
{
  if (!dk)
    return DK_STAT_ARGS;
  if (dk->trace)
  {
    if (!dkt_generate(dk->trace, type, store, store_size))
    {
      return DK_STAT_NORESOURCE; //not enough buffer space
    }
    return DKERR(DK_STAT_OK);
  }
  return DKERR(DK_STAT_INTERNAL);
}

/* HEADER */
/* Prints difference trace table to *store variable (char string)
 * *dk is the container for the table
 * *store is a pointer to a character array to output to
 * store_size is the size of the character array *store
 * return DK_STAT_NOSIG if no DK-Trace header was found
 */
DK_STAT dk_compare_trace(DK *dk, DK_TRACE_TYPE type, char *store, int store_size)
{
  DK_TRACE table;
  if (!dk)
    return DK_STAT_ARGS;
  if (!dk->dktrace || !dk->trace)
    return DK_STAT_NOSIG;
  dkt_init(&table);
  if (!dk->traceheader) //make DK_TRACE from header
  {
    dk->traceheader = DK_MALLOC(sizeof(DK_TRACE));
    if (!dk->traceheader)
      return DKERR(DK_STAT_NORESOURCE);
    dkt_init(dk->traceheader);

    if (!dkt_hdrtotrace(dk->dktrace,dk->traceheader))
    {
      return DK_STAT_NORESOURCE;
    }
  }
  dkt_diff(dk->traceheader, dk->trace, type, &table);
  if (!dkt_generate(&table, type, store, store_size))
  {
    return DK_STAT_NORESOURCE; //not enough buffer space
  }
  return DK_STAT_OK;
}


/* HEADER */
/* Sets the DNS key/policy record manually (no DNS lookup)
 * txtrecord needs to be set to "e=perm;" to force a permanent DNS failure
 * txtrecord needs to be set to "e=temp;" to force a temporary DNS failure
 * Valid DK_TXT types are:
 * DK_TXT_KEY (normal selector record; for <selctor>._domainkey.<domain>)
 * DK_TXT_POLICY (domain policy record; for _domainkey.<domain>)
 */
DK_STAT dk_settxt(DK *dk, DK_TXT recordtype, const char *txtrecord)
{
  char **ptr; //pointer to keyrecord/policyrecord pointer
  if (!dk|| !txtrecord)
    return DK_STAT_ARGS;
  switch (recordtype)
  {
    case DK_TXT_KEY:
      ptr = &dk->keyrec;
      break;
    case DK_TXT_POLICY:
      ptr = &dk->policyrec;
      break;
    default:
      return DK_STAT_ARGS;
  }
  // Free the value iff it is currently set.
  if (*ptr)
  {
    DK_MFREE(*ptr);
  }
  *ptr = dk_strdup(txtrecord);
  return DKERR(DK_STAT_OK);
}

static DK_STAT dkstore_char(DK *dk, char ch)
{
  if (dk->headerlen >= dk->headermax)
  {
    char *hp;
    hp = DK_MALLOC(dk->headermax * 2 + 1024 + 1); /* leave room for null */
    if (!hp)
    {
      return DKERR(DK_STAT_NORESOURCE);
    }
    if (dk->headermax)
    {
      memcpy(hp, dk->header, dk->headerlen);
      DK_MFREE(dk->header);
    }
    dk->header = hp;
    dk->headermax = dk->headermax * 2 + 1024;
  }
  dk->header[dk->headerlen++] = ch;
  dk->headerlinelen++;
  return DKERR(DK_STAT_OK);
}

/* HEADER */
/* Per-message, may be threaded.
 * canon is one of DK_CANON_*.
 * Returns state structure for operation.  Consult statp before using.
 */
DK *dk_sign(DK_LIB *dklib, DK_STAT *statp, int canon)
{
  DK *dk;

  dk = DK_MALLOC(sizeof(DK));
  if (!dk)
  {
    if (statp)
    {
      *statp = DKERR(DK_STAT_NORESOURCE);
    }
    return NULL;
  }
  dk->dkmarker = DKMARK;
  dk->signing = DK_SIGNING_SIGN;
  if (dkinit_new_header(dk) != DK_STAT_OK)
  {
    /* couldn't malloc a header. */
    DK_MFREE(dk);
    if (statp)
    {
      *statp = DKERR(DK_STAT_NORESOURCE);
    }
    return NULL;
  }
  dk->canon = canon; /* TC13-simple, TC13-nofws */
  EVP_SignInit(&dk->mdctx, dklib->md);

  if (statp)
  {
    *statp = DKERR(DK_STAT_OK);
  }
  return dk;
}

/* HEADER */
/* Per-message, may be threaded.
 * Returns state structure for operation.  Consult statp before using.
 */
DK *dk_verify(DK_LIB *dklib, DK_STAT *statp)
{
  DK *dk;

  dk = DK_MALLOC(sizeof(DK));
  if (!dk)
  {
    if (statp)
    {
      *statp = DKERR(DK_STAT_NORESOURCE);
    }
    return NULL;
  }
  dk->dkmarker = DKMARK;
  dk->signing = DK_SIGNING_NOVERIFY; /* wait to verify until we see DK-Signature. */
  if (dkinit_new_header(dk) != DK_STAT_OK)
  {
    /* couldn't malloc a header. */
    DK_MFREE(dk);
    if (statp)
    {
      *statp = DKERR(DK_STAT_NORESOURCE);
    }
    return NULL;
  }
  EVP_VerifyInit(&dk->mdctx, dklib->md);

  if (statp)
  {
    *statp = DKERR(DK_STAT_OK);
  }
  return dk;
}

/* parse an rfc822 address */
/* leave it in the dk_address() format; that is, with the existing
 * first letter, followed by the address */
static DK_STAT dkparse822(char *address, unsigned int offset)
{
  int foundangle = 0;   /* true if it's in angle brackets */
  int foundat = 0;
  char *from, *to;
  int level = 1;

  to = address + 1;
  from = address + offset;
  while (*from)
  {   /* nuke comments. */
    if (*from == ')')
    {
      return DK_STAT_SYNTAX;
    }
    else if (*from == '\\' && from[1])
    {
      /* skip backslash-quoted characters */
      *to++ = *from++;
      *to++ = *from++;
    }
    else if (*from == '"')
    {
      /* we have to ignore parenthesis inside quotes. */
      from++;
      for (;;)
      {
        if (*from == '\0')
        {
          return DK_STAT_SYNTAX;
        }
        else if (*from == '"')
        {
          from++;
          break;
        }
        else if (*from == '\\' && from[1])
        {
          *to++ = *from++;
        }
        *to++ = *from++;
      }
    }
    else if (*from == '(')
    {
      level = 1;
      from++;
      while (level)
      {
        if (*from == '\0')
        {
          return DK_STAT_SYNTAX;
        }
        else if (*from == '(')
        {
          ++level;
        }
        else if (*from == ')')
        {
          --level;
        }
        else if (*from == '\\' && from[1])
        {
          ++from;
        }
        ++from;
      }
    }
    else if (*from == ' ')
    {
      ++from;
    }
    else if (*from == '\t')
    {
      ++from;
    }
    else
    {
      *to++ = *from++;
    }
  } //end while(*from)
  *to = '\0';
  from = address + 1;
  to = address + 1;
  while (*from)
  {
    if (*from == '@')
    {
      foundat = 1;
    }
    if (*from == '\\' && from[1])
    {
      *to++ = *from++;
      *to++ = *from++;
    }
    else if (*from == '<')
    {
      from++;
      to = address + 1;
      foundangle = 1;
      foundat = 0;
    }
    else if (*from == ',' || *from == ':' )
    {
      from++;
      to = address + 1;
      foundat = 0;
    }
    else if (foundangle && *from == '>')
    {
      break;
    }
    else if (*from == ';')
    {
      break;
    }
    else
    {
      *to++ = *from++;
    }
  }
  *to = '\0';
  if (foundat)
  {
    return DK_STAT_OK;
  }
  else if (!address[1])
  {
    return DK_STAT_OK;
  }
  else
  {
    return DK_STAT_SYNTAX;  /* no @ in the address */
  }
}

/* Given a list of key=value; pairs, find all the keys found in letters.
 * Store the value in the corresponding entry in values[].
 * Modifies list to insert nulls in the place of the semicolons which terminate
 * each of the values except possibly the last.
 * You can only call dkparselist() once on a given list.
 * Caller must ensure that values[] is as large as strlen(letters)
 * According to the spec, a value can have embedded spaces in it, however none
 * of the existing values need spaces, so we always remove them.
 */

static DK_STAT dkparselist(char *list, char *letters, char *values[])
{
  char key;
  int i;
  char *value;

  /* start with all args unset */
  for (i = 0; letters[i]; i++)
  {
    values[i] = NULL;
  }
  key = 0;
  while (*list)
  {
    if ((*list == ' ')||(*list == '\t')||(*list == '\r')||(*list == '\n'))
    {
      list++;
    }
    else if (*list == '=')
    {
      char *ws;

      ++list;
      value = list;
      ws = list;
      while (1)
      {
        /* copy up to null or semicolon, deleting whitespace as we go */
        *ws = *list;
        if ((*list == ' ')||(*list == '\t')||(*list == '\r')||(*list == '\n'))
        {
          /* ignore */
        }
        else if (!*list)
        {
          break;
        }
        else if (*list == ';')
        {
          *ws = '\0';
          list++;
          break;
        }
        else
        {
          ws++;
        }
        list++;
      }
      if (!key)
      {
        return DK_STAT_SYNTAX; /* we didn't get a key. TC22 */
      }
      /* if we find a matching letter, remember the value */
      for (i = 0; letters[i]; i++)
      {
        if (key == letters[i])
        {
          if (values[i])
          {
            return DK_STAT_SYNTAX; /* no duplicate keys. TC23 */
          }
          values[i] = value;
        }
      }
      key = 0;
    }
    else
    {
      if (key)
      {
        return DK_STAT_SYNTAX; /* they already gave us a key. TC24 */
      }
      key = *list++;
      if (!islower((int)key))
      {
        return DK_STAT_SYNTAX; /* must be lowercase letter. TC25 */
      }
    }
  }
  if (key)
  {
    return DK_STAT_SYNTAX; /* we ended up with an extra key. TC25-1 */
  }
  return DK_STAT_OK;
}

/* HEADER */
/* DEPRECATED in favor of calling dk_setopts()
 * set option to remove dupe headers
 * should be called after dk_sign();
 * any int NOT 0 turns dupe removal on
 */
DK_STAT dk_remdupe(DK *dk,int i)
{
  if (i != 0)
    return dk_setopts(dk,DKOPT_RDUPE);
  return DK_STAT_OK;
}


/* HEADER */
/* Returns the policy flags belonging to the signing domain.
 * Sender: overrides From:, and the d= entry in the DK-Sig overrides both.
 * If the policy flags were not successfully fetched, DK_FLAG_SET will not
 * be set.
 */
DK_FLAGS dk_policy(DK *dk)
{
  char *query, *results, *flags[2];
  char *domain;
  int dkf = 0;

  if (!dk)
    return 0;
  domain = NULL;
  if (dk->dksign)
  {
    domain = dk->domain;
  }
  if (!domain)
  {
    domain = dk_from(dk);
  }
  if (!domain)
  {
    return 0;
  }

  query = DK_MALLOC(strlen("_domainkey.") + strlen(domain) + 1);
  if (query)
  {
     /* allow user to supply the DNS TXT policy record */
    if (!dk->policyrec)
    {
      sprintf(query, "_domainkey.%s", domain);
      results = dns_text(query);
      DK_MFREE(query);
    }
    else
    {
      results = dk_strdup(dk->policyrec);
    }

    if (!strcmp(results,"e=perm;"))
    {
    }
    else if (!strcmp(results,"e=temp;"))
    {
    }
    else
    {
      dkparselist(results, "ot", flags);

      if (flags[0] && *flags[0] == '-')  /* TC36 */
      {
        dkf |= DK_FLAG_SIGNSALL;
      }
      if (flags[1] && *flags[1] == 'y')  /* TC36-1 */
      {
        dkf |= DK_FLAG_TESTING;
      }
      dkf |= DK_FLAG_SET;
    }
    DK_MFREE(results);
  }
  return dkf;
}

/*
dkhash
Internal function. Hashes in a single character, Will NOT has in ' ' or '\t'
if in NOFWS canon. Otherwise tracks \r and \r\n and hashes
them accordingly with the rest of the message.
Should ONLY be called when
  dk->signing == DK_SIGNING_SIGN||DK_SIGNING_VERIFY
otherwise its pointless
*/
static void dkhash(DK *dk, const unsigned char *ptr)
{
#ifdef DK_DEBUG
  if ((dk->signing != DK_SIGNING_SIGN)&&(dk->signing != DK_SIGNING_VERIFY))
  {
    //called when we shouldnt of, this will break the sig
    fprintf(stderr,"\nDKHASH() called for \'%c\' in mode: %i\n",*ptr,dk->signing);
  }
#endif
  if (dk->canon == DK_CANON_NOFWS && (*ptr == ' ' || *ptr == '\t'))
  {
    return;
  }

  if ((dk->in_headers && dk->trace) && (dk->opts & DKOPT_TRACE_H))
  {
    if (dk->canon == DK_CANON_NOFWS)
    {
      if (*ptr != '\r')
      {
        if (*ptr == '\n')
        {
          dk->trace->ccounts_H[10]++;
          dk->trace->ccounts_H[13]++;
        }
        else
        {
          dk->trace->ccounts_H[(int) *ptr]++;
        }
      }
    }
    else
    {
      dk->trace->ccounts_H[(int) *ptr]++;
    }
  }

  if (*ptr == '\r' && ((dk->state & 1) == 0))
  {
    dk->state++;
  }
  else if (*ptr == '\n' && ((dk->state & 1) == 1))
  {
    dk->state++;
  }
  else
  {
    while (dk->state >= 2)
    {

#ifndef DK_HASH_BUFF
      EVP_DigestUpdate(&dk->mdctx, "\r\n", 2);
#else
      /* buffer hack */
      dk->hash_buff[dk->hash_buff_len++] = '\r';
      dk->hash_buff[dk->hash_buff_len++] = '\n';
      if (dk->hash_buff_len >= (DK_BLOCK - 1))
      {
        EVP_DigestUpdate(&dk->mdctx, dk->hash_buff, dk->hash_buff_len);
        dk->hash_buff_len = 0;
      }
      /* buffer hack */
#endif
      if ((!dk->in_headers && dk->trace) && (dk->opts & DKOPT_TRACE_B))
      {
        dk->trace->ccounts_B[10]++;
        dk->trace->ccounts_B[13]++;
      }
#ifdef DK_DEBUG
      fprintf(stderr,"\r\n");
#endif
      dk->state -= 2;
    }
    if (dk->state)
    {
      if (dk->canon == DK_CANON_SIMPLE)//if nofws we ignore \r
      {
#ifndef DK_HASH_BUFF
        EVP_DigestUpdate(&dk->mdctx, "\r", 1);
#else
        /* buffer hack */
        dk->hash_buff[dk->hash_buff_len++] = '\r';
        if (dk->hash_buff_len >= (DK_BLOCK - 1))
        {
          EVP_DigestUpdate(&dk->mdctx, dk->hash_buff, dk->hash_buff_len);
          dk->hash_buff_len = 0;
        }
        /* buffer hack */
#endif
        if ((!dk->in_headers && dk->trace) && (dk->opts & DKOPT_TRACE_B))
        {
          dk->trace->ccounts_B[13]++;
        }
#ifdef DK_DEBUG
        fprintf(stderr,"\r");
#endif
      }
      dk->state --;
    }
#ifndef DK_HASH_BUFF
    EVP_DigestUpdate(&dk->mdctx, ptr, 1);
#else
    /* buffer hack */
    dk->hash_buff[dk->hash_buff_len++] = *ptr;
    if (dk->hash_buff_len >= (DK_BLOCK - 1))
    {
      EVP_DigestUpdate(&dk->mdctx, dk->hash_buff, dk->hash_buff_len);
      dk->hash_buff_len = 0;
    }
    /* buffer hack */
#endif

    if ((!dk->in_headers && dk->trace) && (dk->opts & DKOPT_TRACE_B))
    {
      dk->trace->ccounts_B[(int) *ptr]++;
    }

#ifdef DK_DEBUG
    fprintf(stderr,"%c", *ptr);
#endif
  }
}

/* process headers if there's a h=*/
/* dk->start_signed + 1 is the offset into headers pointing at the first header after DK-Sig */
/* Changed to fix h= handling, checks if header is listed in h=
 *  handles duplicate Header items properly. (see section 3.3 h= draft-02)
 * We don't "look" for missing headers, maybe later.... -Tim
 */
static DK_STAT dkheaders_header(DK *dk)
{
  char *header_line_start,*header_label_end;
  char header_list[1024];
  char header_label[1024];

  char *p;
  //search hack redo later? -tim
  if (snprintf(header_list,sizeof(header_list),":%s:",dk->headers) >= sizeof(header_list))
  {
    //header list is too large for buffer
    return DKERR(DK_STAT_SYNTAX);
  }

  /*convert to all lowercase*/
  for (p = header_list; p[0] != '\0'; ++p)
  {
    p[0] = tolower(p[0]);
  }

  header_label[0] = ':';
  //first char in header_line_start is '\0' unless signing
  header_line_start = dk->header + dk->start_signed;
  if (dk->signing != DK_SIGNING_SIGN)
  {
    ++header_line_start;
  }
  while (1)
  {
    if (header_line_start >= (dk->header + dk->headerlen))
    {
      return DKERR(DK_STAT_OK);  //done reading headers
    }
    header_label_end = header_line_start;
    p = &header_label[1];
    while (p < (header_label + sizeof(header_label) - 2))
    {
      if (header_label_end[0] != ':')
      {
        p[0] = tolower(header_label_end[0]);
        ++p;
        ++header_label_end;
      }
      else
      {
        break;
      }
    }
    p[0] = ':';
    p[1] = '\0';
    //fprintf(stderr,"searching for: %s in %s\n",header_label, header_list);
    //if the header is found in the h= list
    if (strstr(header_list, header_label) != NULL)
    {
      //Found listed header, hash it in
      while(header_line_start[0] != '\0')
      {
        //we kept folded headers \r\n as markers -Tim
        if ((header_line_start[0] == '\n')||(header_line_start[0] == '\r'))
        {
          //if simple we keep the folded lines
          //if nofws we ignore it to unwrap it
          if (dk->canon == DK_CANON_NOFWS)
          {
            ++header_line_start;
            continue;
          }
        }
        dkhash(dk,&header_line_start[0]);
        ++header_line_start;
      }
      dkhash(dk, "\r");
      dkhash(dk, "\n");
    }
    else //skip hashing this header
    {
      while(header_line_start[0] != '\0')
      {
        ++header_line_start;
      }
    }
    //goto next header
    ++header_line_start;

  }//end while
}
/* dkheaders
  When Signing (DK_SIGNING_SIGN), Hashes in ALL headers and Greps out Sender:/From: headers

  When Verifying, reads headers until DK-Sig is found
  then
  If an h= tag is found, Greps out Sender:/From: headers, then calls dkheaders_header
    to hash in the listed headers
  If NO h= tag is present, it Greps out Sender:/From: headers as well as hashes in the
    headers that follow the DK-Sig header.
*/
static DK_STAT dkheaders(DK *dk)
{
  int i;

  for (i = 0; i < dk->headerlen; i++)
  {
    if (dk->headers && dk->signing == DK_SIGNING_VERIFY) //if h= wait till after parsing
    {
      //NOOP
    }
    else if (dk->canon == DK_CANON_NOFWS && (dk->header[i] == '\r' || dk->header[i] == '\n'))
    {
      //NOOP
    }
    /* Newcode */
    else if ((dk->opts & DKOPT_RDUPE)&&(dk->signing == DK_SIGNING_SIGN))
    {
      //NOOP
    }
    else if ((dk->signing == DK_SIGNING_SIGN)||(dk->signing == DK_SIGNING_VERIFY))
    {
      //we wont bother calling dkhash unless we are signing or verifying -Tim
      if (dk->header[i])
      {
        dkhash(dk, dk->header + i);
      }
      else //terminate end of header line
      {
        dkhash(dk, "\r");
        dkhash(dk, "\n");
      }
    }
    /* Newcode end */

    if (i==0 || dk->header[i-1] == '\0')
    {
      if (!strncasecmp(dk->header + i, "From:", 5))
      {
        /* Remember the From: and forget the current. */
        if (dk->from)
        {
          /* if we already got a From: header, fuhgeddabout it. */
          return DKERR(DK_STAT_SYNTAX);
        }
        dk->from = dk_strdup(dk->header + i);
        if (dkparse822(dk->from, 5) != DK_STAT_OK)
        {
          DK_MFREE(dk->from);
          dk->from = 0;
          return DKERR(DK_STAT_SYNTAX);
        }
      }
      else if (!strncasecmp(dk->header + i, "Sender:", 7))
      {
        if (dk->sender)
        {
          /* if we already got a Sender: header, fuhgeddabout it. */
          return DKERR(DK_STAT_SYNTAX);
        }
        if (dk->signing != DK_SIGNING_NOVERIFY)
        {
          /* only remember the Sender if we're verifying already. */
          dk->sender = dk_strdup(dk->header + i);
          if (dkparse822(dk->sender, 7) != DK_STAT_OK)
          {
            DK_MFREE(dk->sender);
            dk->sender = 0;
            return DKERR(DK_STAT_SYNTAX);
          }
        }
        else if (!dk->sender_beforesign)
        {
          dk->sender_beforesign = dk_strdup(dk->header + i);
          if (dkparse822(dk->sender_beforesign, 7) != DK_STAT_OK)
          {
            DK_MFREE(dk->sender_beforesign);
            dk->sender_beforesign = 0;
            return DKERR(DK_STAT_SYNTAX);
          }
        }
      }
      else if (!strncasecmp(dk->header + i, "DomainKey-Trace:", 16))
      {
        if (dk->trace && !dk->dktrace)//only set this once
        {
          dk->dktrace = dk->header + i;
        }
      }
      else if (!strncasecmp(dk->header + i, "DomainKey-Signature:", 20))
      {
        int thisheaderlen = strlen(dk->header + i);

        /* Do not sign email that already has a dksign unless the Sender was found first, 3.5.2 TC41, TC41-1*/
        if (dk->signing == DK_SIGNING_SIGN && !dk->sender)
        {
          return DKERR(DK_STAT_SYNTAX);
        }
        /* check the outermost (first encountered) signature (need to fix when multiple sigs are present)
        * ONLY if we are verifying, if we are signing then ignore it (sender before dk-sig) -Tim
        */
        if ((!dk->dksign)&&(dk->signing != DK_SIGNING_SIGN))
        {
          char *values[7];  /* dsbchqa */
          dk->dksign = dk->header + i;
          /* parse the dksign header .*/
          if (dkparselist(dk->dksign + 20,"dsbchqa", values) != DK_STAT_OK)
          {
            return DKERR(DK_STAT_SYNTAX);
          }

          dk->domain = values[0];
          dk->selector = values[1];
          dk->signature = values[2];
          if (!dk->selector || !dk->domain || !dk->signature)
          {
            /* we really do need to have a domain, selector and key. TC21 TC40 */
            return DKERR(DK_STAT_NOSIG);
          }

          if (!values[3])
          {
            dk->canon = DK_CANON_SIMPLE;
          }
          else if (!strcasecmp(values[3], "simple"))
          {
            dk->canon = DK_CANON_SIMPLE;
          }
          else if (!strcasecmp(values[3], "nofws"))
          {
            dk->canon = DK_CANON_NOFWS;
          }
          else
          {
            return DKERR(DK_STAT_SYNTAX); /* TC42 */
          }

          dk->headers = values[4];

          if (values[5] && strcasecmp(values[5], "dns")) /* TC42-2 */
          {
            return DKERR(DK_STAT_SYNTAX);
          }
          if (values[6] && strcasecmp(values[6], "rsa-sha1")) /* TC42-3 */
          {
            return DKERR(DK_STAT_SYNTAX);
          }

        }
        /* if we're waiting to verify, start now. */
        if (dk->signing == DK_SIGNING_NOVERIFY)
        {
          dk->signing = DK_SIGNING_VERIFY; /* the signature starts here */
          i += thisheaderlen;
          if (dk->start_signed == 0) //we should set it only once right?
          {
            dk->start_signed = i;
          }
        }
      }
      //end trace
    }
  }
  if ((!dk->from)||(!dk_from(dk)))
  {
    /* No From:, 3.1 says that it's no good..  TC11/TC16 */
    return DKERR(DK_STAT_SYNTAX);
  }
  if (dk->signing == DK_SIGNING_NOVERIFY)
  {
    /* No DK-Sig: should return No Signature. */
    return DKERR(DK_STAT_NOSIG);
  }
  if (dk->headers && dk->signing == DK_SIGNING_VERIFY)
  {
    return dkheaders_header(dk);
  }
  if ((dk->signing == DK_SIGNING_SIGN)&&(dk->opts & DKOPT_RDUPE)) //remove dupe headers for sig
  {
    DK_STAT ret;
    dk->headers = DK_MALLOC(dk->headermax);
    (void *)dk_headers(dk, dk->headers);
    ret = dkheaders_header(dk);
    DK_MFREE(dk->headers);
    return ret;
  }
  return DKERR(DK_STAT_OK);
}

/* HEADER */
/* Copies the header names that were signed into the pointer.
 * Returns the number of bytes copied.
 * ptr may be NULL, in which case the bytes are just counted, not copied.
 * Feel free to call this twice; once to get the length, and again to
 * copy the data.
 * NOTE: If the return value is 0 then an error occured.
 *	It's a good idea to check for this
 */
int dk_headers(DK *dk, char *ptr)
{
  register int len = 0;
  register int label_len = 0;
  int list_size;
  char *header_start = NULL;
  char *header_end = NULL;
  char *h_label = NULL;
  char *h_list = NULL;

  char *dupe_list = NULL;


  if (ptr) //if you dont check if return is 0, ptr can be anything
  	ptr[0] = 0;

  if ((!dk)||(dk->dkmarker != DKMARK))
  {
    return 0;
  }
  list_size = dk->headermax;

  h_list = (char *) DK_MALLOC(list_size);
  if (!h_list)
    return 0;
  memset(h_list,0,list_size);
  h_list[len++] = ':';

  header_start = dk->header + dk->start_signed;

  for (header_end = header_start; header_end < (dk->header + dk->headerlen); header_end++)
  {
    if (*header_end == '\0')
    {
      header_start = header_end+1;//point to start of next line
    }
    else if (*header_end == ':' && header_start)
    {
      label_len = (header_end - header_start) + 1;
	  //grow list array
	  if ((len+label_len) >= list_size)
	  {
	  	char *temp = NULL;
		list_size += dk->headermax;
		temp = DK_MALLOC(list_size);
		if (!temp)
		{
			len = 1; //out of memory?
			goto END;
		}
		memset(temp,0,list_size);
		memcpy(temp,h_list,len);
		DK_MFREE(h_list);
		h_list = temp;
	  }

      memcpy(h_list + len, header_start, label_len);
      len += label_len;
      header_start = NULL;
    }
  }

  if (dk->opts & DKOPT_RDUPE)
  {

    h_label = (char *) DK_MALLOC(list_size);
	dupe_list = (char *) DK_MALLOC(list_size);

    if (!h_label || !dupe_list)
	{
      len = 1;
	  goto END;
	}
    memset(h_label,0,list_size);
    memset(dupe_list,0,list_size);

    len = 0;
  	header_start = h_list;
	for (header_end = header_start + 1; *header_end != '\0'; header_end++)
	{
		if (*header_end == ':')
		{
			label_len = (header_end - header_start)+1;
	        memcpy(h_label, header_start, label_len);
    	    h_label[label_len] = 0;
			if ((strstr(h_list,h_label) == header_start)  && (strstr(header_start + 1,h_label) == NULL) )
			{
				memcpy(dupe_list + len ,h_label,label_len);
				len += label_len -1;
			}
			header_start = header_end;
		}
	}
	len++;
	if (ptr)
		memcpy(h_list, dupe_list, len);
  }

  if ((ptr != NULL)&&(len > 1))
  {
    memcpy(ptr,h_list+1,(len-2));//dont count the prefix and postfix'd ":"
    ptr[len-2] = 0;
  }
  END:
  if (h_label)
    DK_MFREE(h_label);
  if (h_list)
    DK_MFREE(h_list);
  if (dupe_list)
    DK_MFREE(dupe_list);

  return --len;

}

/* HEADER */
/* Must NOT include dots inserted for SMTP encapsulation.
 * Must NOT include CRLF.CRLF which terminates the message.
 * Otherwise must be exactly that which is sent or received over the SMTP session.
 * May be called multiple times (not necessary to read an entire message into memory).
 */
DK_STAT dk_message(DK *dk, const unsigned char *ptr, size_t len)
{
  DK_STAT st;
  int tb=0,th=0;
  if (!dk)
  {
    return DK_STAT_ARGS;
  }
  if (dk->dkmarker != DKMARK)
  {
    return DK_STAT_ARGS;
  }
  if (len && !ptr)
  {
    return DKERR(DK_STAT_ARGS);
  }
  if (dk->trace && (dk->opts & DKOPT_TRACE_b))
    tb = 1;
  if (dk->trace && (dk->opts & DKOPT_TRACE_h))
    th = 1;

  while (len--)
  {
    if ((*ptr == '\n') && (dk->last_char != '\r'))
    {
      //input not formatted correctly
      //CR should preceed LF
      return DKERR(DK_STAT_SYNTAX);
    }
    /* parse headers */
    if (!dk->in_headers)
    {
      dkhash(dk, ptr); //hash body of message
      //precanon probably wont be accurate as dk_message() only takes in SMTP format -Tim
      if (tb)
        dk->trace->ccounts_b[(int) *ptr]++;
    }
    else if (*ptr == '\n' && dk->headerlinelen != 0)
    {
      /* beginning a new line, but we can't do anything until we get a char. */
      dk->headerlinelen = 0;
    }
    else if (*ptr == '\r')
    {
      /* ignore carriage-returns, even bare ones.  We'll add them back in later.*/
      if (dk->last_char == '\r') //keep embedded CR
      {
        if (dkstore_char(dk, '\r') != DK_STAT_OK)
        {
          return DKERR(DK_STAT_NORESOURCE);
        }
        if (th)
          dk->trace->ccounts_h[13]++;
      }
    }
    else if (dk->headerlinelen)
    {

      if (dk->last_char == '\r') //keep embedded CR
      {
        if (dkstore_char(dk, '\r') != DK_STAT_OK)
        {
          return DKERR(DK_STAT_NORESOURCE);
        }
        if (th)
          dk->trace->ccounts_h[13]++;
      }

      /* if we're not starting a new header, just store it */
      if (dkstore_char(dk, *ptr) != DK_STAT_OK)
      {
        return DKERR(DK_STAT_NORESOURCE);
      }
      if (th)
        dk->trace->ccounts_h[(int) *ptr]++;
    }
    else if (*ptr == ' ' || *ptr == '\t')
    {
      /* a new header ... starting with whitespace.  Must be continuation */
      /* just remember the whitespace */
      //preserv folded headers for simple canon -Tim
      if (dkstore_char(dk, '\r') != DK_STAT_OK)
      {
        return DKERR(DK_STAT_NORESOURCE);
      }
      if (dkstore_char(dk, '\n') != DK_STAT_OK)
      {
        return DKERR(DK_STAT_NORESOURCE);
      }
      if (dkstore_char(dk, *ptr) != DK_STAT_OK)
      {
        return DKERR(DK_STAT_NORESOURCE);
      }
      if (th)
      {
        dk->trace->ccounts_h[10]++;
        dk->trace->ccounts_h[13]++;
        dk->trace->ccounts_h[(int) *ptr]++;
      }

    }
    else if (*ptr == '\n')
    {
      /* an empty line terminates header processing */
      /* terminate the previous header */
      if (dkstore_char(dk, '\0') != DK_STAT_OK)
      {
        return DKERR(DK_STAT_NORESOURCE);
      }
      if (th)
      {
        dk->trace->ccounts_h[10]++;
        dk->trace->ccounts_h[13]++;
      }
      if (tb)
      {
        dk->trace->ccounts_b[10]++;
        dk->trace->ccounts_b[13]++;
      }
      st = dkheaders(dk);
      dk->in_headers = 0;
      dkhash(dk, "\r");
      dkhash(dk, "\n");

      if (st != DK_STAT_OK)
      {
        return st;
      }
    }
    else
    {
      /* we're starting a new header.  Terminate the previous one. */
      if (dkstore_char(dk, '\0') != DK_STAT_OK)
      {
        return DKERR(DK_STAT_NORESOURCE);
      }
      /* remember the first character of a new header. */
      if (dkstore_char(dk, *ptr) != DK_STAT_OK)
      {
        return DKERR(DK_STAT_NORESOURCE);
      }
      if (th)
      {
        dk->trace->ccounts_h[10]++;
        dk->trace->ccounts_h[13]++;
        dk->trace->ccounts_h[(int) *ptr]++;
      }
    }
    dk->last_char = *ptr; //remember last character processed
    ptr++;
  }
  return DKERR(DK_STAT_OK);
}

/* HEADER */
/* DEPRECATED in favor of calling dk_address().
 * Returns a pointer to a null-terminated domain name portion of an RFC 2822 address.
 * If a Sender: was encountered, it returns that domain.  Otherwise,
 * if a From: was encountered, it returns that domain.  Otherwise,
 * return NULL.
 * return NULL if no domain name found in the address.
 * return NULL if the dk is unusable for any reason.
 * return NULL if the address is unusable for any reason.
 */
char *dk_from(DK *dk)
{
  char *s;

  if (!dk)
  {
    return NULL;
  }
  if (dk->dkmarker != DKMARK)
  {
    return NULL;
  }

  s = NULL;
  if (dk->sender)
  {
    s = dk->sender; /* TC14-1 */
  }
  else if (dk->sender_beforesign && (dk->signing == DK_SIGNING_NOVERIFY))
  {
    s = dk->sender_beforesign;
  }
  else if (dk->from)
  {
    s = dk->from; /* TC14-2 */
  }
  if (s && *s && s[1] && s[1] != '@')
  {
    s = strchr(s, '@') + 1;
    if (*s == '\0')
    {
      //make sure we have an actual domain after @
      s = NULL;
    }
  }
  else
  {
    s = NULL;
  }
  return s;
}

/* HEADER */
/* Returns a pointer to the selector name used or NULL if there isn't one
 * Added by rjp
 */
const char *dk_selector(DK *dk)
{
  if (!dk) return NULL;
  return (dk->selector);
}

/* HEADER */
/* Returns a pointer to the domain name used or NULL if there isn't one
 */
const char *dk_domain(DK *dk)
{
  if (!dk) return NULL;
  return (dk->domain);
}

/* HEADER */
/*
 * Returns a pointer to a string which begins with "N", "S", or "F",
 * corresponding to None, Sender: and From:, respectively.
 * This single character is followed by a null-terminated RFC 2822 address.
 * The first character is "N" if no valid address has been seen yet,
 * "S" if the address came from the Sender: field, and "F" if the
 * address came from the From: field.
 */
char *dk_address(DK *dk)
{
  if ((!dk)||(dk->dkmarker != DKMARK))
  {
    return "N";
  }
  if (dk->sender)
  {
    return dk->sender; /* TC14-3 */
  }
  if (dk->from)
  {
    return dk->from; /* TC14-4 */
  }
  return "N";     /* TC14-5 */
}

/* HEADER */
/*
 * Returns a pointer to a null-terminated string containing the granularity
 * value found in the selector DNS record, if any, but only after dk_end
 * has been called. Otherwise returns NULL.
 */
char *dk_granularity(DK *dk)
{
  if (!dk)
  {
    return NULL;
  }
  if (dk->dkmarker != DKMARK)
  {
    return NULL;
  }
  return dk->granularity;
}

/* HEADER */
/*
 * Called at end-of-message (before response to DATA-dot, if synchronous with SMTP session).
 * If verifying, returns signature validity.
 * This does not calculate the signature.  Call dk_getsig() for that.
 * Flags are returned indirectly through dkf.
 * If you pass in NULL for dkf, the flags will not be fetched.
 * If there is a DK-Sig line, the d= entry will be used to fetch the flags.
 * Otherwise the Sender: domain will be used to fetch the flags.
 * Otherwise the From: domain will be used to fetch the flags.
 *
 * NOTE: If for some reason dk_end() returns an error (!DK_STAT_OK) dk_policy() should be called
 * to get the domain signing policy (o=) and handle accordingly.
 * dkf (selector flags) wont be set if dk_end() returns
 * DK_STAT_NOSIG
 * DK_STAT_NOKEY
 * DK_STAT_SYNTAX
 * DK_STAT_NORESOURCE
 * DK_STAT_BADKEY
 * DK_STAT_CANTVERIFY
 */
DK_STAT dk_end(DK *dk, DK_FLAGS *dkf)
{
  if ((!dk)||(dk->dkmarker != DKMARK))
  {
    return DK_STAT_ARGS;
  }

  /* yes, the only way we can still be in the headers at the end of
     the message is if they supplied us with a message that not only
     has no body, but also lacks the blank line terminating the
     headers.  Still, we have to handle it correctly.  TC13-nobody */
  if (dk->in_headers)
  {
    DK_STAT st;

    if (dkstore_char(dk, '\0') != DK_STAT_OK)
    {
      return DKERR(DK_STAT_NORESOURCE);
    }
    st = dkheaders(dk);
    if (st != DK_STAT_OK)
    {
      return st;
    }
  }

  switch (dk->signing)
  {
  case DK_SIGNING_SIGN:
  case DK_SIGNING_VERIFY:
    //force hash final CRLF to terminate email
#ifdef DK_HASH_BUFF
    //clean out hash buffer
    dk->hash_buff[dk->hash_buff_len++] = '\r';
    dk->hash_buff[dk->hash_buff_len++] = '\n';
    EVP_DigestUpdate(&dk->mdctx, dk->hash_buff, dk->hash_buff_len);
    dk->hash_buff_len = 0;
#else
    EVP_DigestUpdate(&dk->mdctx, "\r\n", 2);
#endif
#ifdef DK_DEBUG
    fprintf(stderr,"\r\n");
#endif

  }

  switch (dk->signing)
  {
  case DK_SIGNING_SIGN:
  case DK_SIGNING_NOSIGN:
    if (!dk->from)
    {
      return DKERR(DK_STAT_SYNTAX);
    }
    return DKERR(DK_STAT_OK);
  case DK_SIGNING_VERIFY:
  case DK_SIGNING_NOVERIFY:
    {
      unsigned char md_value[1024];
      int md_len=0;
      char *s = NULL; //pointer to domain portion of email addy
      char *sndr = NULL;
      char *domainkeys; /* malloc'ed */
      char *txtrec; /* malloc'ed */
      char *pubkeyvals[4];
      int i;
      DK_STAT st;

      BIO *bio, *b64;
      EVP_PKEY *publickey;

      /* make sure that we got a header */
      if (!dk->dksign)
      {
        return DKERR(DK_STAT_NOSIG); /* TC11 */
      }

      /* make sure that domain on the From: matches the d data. TC26 */
      /* Or is a subdomain of the d data.  TC26-1, etc. */
      if (dk->sender)
      {
        sndr = dk->sender;
      }
      else if (dk->sender_beforesign && (dk->signing == DK_SIGNING_NOVERIFY))
      {
        sndr = dk->sender_beforesign;
      }
      else
      {
        sndr = dk->from;
      }

      if (!sndr)
      {
        return DKERR(DK_STAT_SYNTAX);
      }
      /* we already know that sndr has an '@' in it; otherwise it would not
      * have passed dkparse822. */
      
      /* sndr can also be a one-character string if the from/sender header
      * was there but empty */
      if (!(s = strchr(sndr, '@')))
      {
        return DKERR(DK_STAT_SYNTAX);
      }
      s++; // we skip the tag

      i = (int)strlen(s);
      if (strcasecmp(dk->domain, s))
      {
        for (; md_len < i; md_len++)
        {
          if (s[md_len] == '.')
          {
            if (!strcasecmp(dk->domain, s + md_len + 1))
            {
              break;
            }
          }
        }
      }
      if (md_len == i)
      {
        return DKERR(DK_STAT_SYNTAX);
      }

      /* convert their signature from base64 into binary */
      bio = BIO_new_mem_buf(dk->signature, -1);
      b64 = BIO_new(BIO_f_base64());
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
      BIO_push(b64, bio);
      md_len = BIO_read(b64, md_value, sizeof(md_value));
      BIO_free_all(b64);
      if (md_len >= sizeof(md_value))
      {
        return DKERR(DK_STAT_NORESOURCE);
      }

      /* allow user to supply the DNS TXT key record */
      if (!dk->keyrec )
      {
        /* get the s data and the d data and lookup s._domainkey.d */
        domainkeys = DK_MALLOC(strlen(dk->selector) + strlen(dk->domain) + strlen("._domainkey.") + 1);
        if (!domainkeys)
        {
          return DKERR(DK_STAT_NORESOURCE);
        }
        sprintf(domainkeys, "%s._domainkey.%s", dk->selector, dk->domain);
        txtrec = dns_text(domainkeys);
        DK_MFREE(domainkeys);
      }
      else
      {
        txtrec = dk_strdup(dk->keyrec);
      }

      if (!strcmp(txtrec,"e=perm;")) /* TC31 */
      {
        DK_MFREE(txtrec);
        return DKERR(DK_STAT_NOKEY);
      }

      if (!strcmp(txtrec,"e=temp;")) /* TC30 */
      {
        DK_MFREE(txtrec);
        return DKERR(DK_STAT_CANTVRFY);
      }

      if (dkparselist(txtrec, "ptog", pubkeyvals) != DK_STAT_OK)
      {
        DK_MFREE(txtrec);
        return DKERR(DK_STAT_BADKEY);
      }
      if (dkf) //set this asap
      {
        /* TC35 and TC37 */
        if (pubkeyvals[1] && *pubkeyvals[1] == 'y')
        {
          *dkf |= DK_FLAG_TESTING;
        }
        /* tell them that we got the g= flag.  This means that the entire
         * address matches, not just the domain name */
        if (pubkeyvals[3] && *pubkeyvals[3])
        {
          *dkf |= DK_FLAG_G;
        }
        *dkf |= DK_FLAG_SET;
      }
      /* Store the granularity, if any, and check it against the local part
       * of the sending address */
 
      if (pubkeyvals[3] && *pubkeyvals[3])
      {
        dk->granularity = dk_strdup(pubkeyvals[3]);
		// Note that sndr has a leading 'F' or 'S' 
        if (strncasecmp(dk->granularity, sndr+1, strcspn(sndr+1,"@")))
		{
	        DK_MFREE(txtrec);
	  		return DKERR(DK_STAT_GRANULARITY);
		}
      }
      if (!pubkeyvals[0])
      {
        DK_MFREE(txtrec);
        return DKERR(DK_STAT_NOKEY); /* TC27 */
      }

      if (!*pubkeyvals[0])
      {
        DK_MFREE(txtrec);
        return DKERR(DK_STAT_REVOKED); /* TC27 */
      }

      /* convert their public key from base64 into binary */
      bio = BIO_new_mem_buf(pubkeyvals[0], -1);
      if (!bio)
      {
        DK_MFREE(txtrec);
        return DKERR(DK_STAT_NORESOURCE);
      }
      b64 = BIO_new(BIO_f_base64());
      if (!b64)
      {
        DK_MFREE(txtrec);
        BIO_free(bio);
        return DKERR(DK_STAT_NORESOURCE);
      }
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
      BIO_push(b64, bio);
      publickey = d2i_PUBKEY_bio(b64, NULL);
      BIO_free_all(b64);
      DK_MFREE(txtrec);
      if (!publickey)
      {
        return DKERR(DK_STAT_BADKEY);
      }

      /* using that key, verify that the digest is properly signed */
      i = EVP_VerifyFinal(&dk->mdctx, md_value, md_len, publickey);

      if (i > 0)
      {
        st = DK_STAT_OK;
      }
      else
      {
        st = DK_STAT_BADSIG;
      }
      EVP_PKEY_free(publickey);
      return DKERR(st);
    }
  }//End switch
  return DK_STAT_ARGS;
}


/* HEADER */
/*
 * DEPRECATED in favor of calling dk_end and dk_policy() directly.
 * If you pass in NULL for dkf, the policy flags will not be fetched.
 * If the message verified okay, the policy flags will not be fetched.
 */
DK_STAT dk_eom(DK *dk, DK_FLAGS *dkf)
{
  DK_STAT dkstat;

  dkstat = dk_end(dk, dkf);  /* TC36* */
  if (dkf && dkstat != DK_STAT_OK)
  {
    *dkf |= dk_policy(dk);
  }
  return dkstat;
}


/* HEADER */
/*
 *
 * privatekey is the private key used to create the signature; It should contain
 * the entire contents of a PEM-format private key file, thusly it will begin with
 * -----BEGIN RSA PRIVATE KEY-----.  It should be null-terminated.
 */
size_t dk_siglen(void *privatekey)
{
  BIO *bio;
  EVP_PKEY *pkey;
  size_t len;

  if (!privatekey)
  {
    return 0;
  }

  bio = BIO_new_mem_buf(privatekey, -1);
  pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);

  len = (EVP_PKEY_size(pkey) + 2) / 3 * 4;
  EVP_PKEY_free(pkey);
  return len;
}


/* HEADER */
/*
 * Sets buf to a null-terminated string.
 * If the message is being signed, signature is stored in the buffer.
 * If the message is being verified, returns DK_STAT_INTERNAL.
 * privatekey is the private key used to create the signature; It should contain
 * the entire contents of a PEM-format private key file, thus it will begin with
 * -----BEGIN RSA PRIVATE KEY-----.  It should be null-terminated.
 * If you pass in NULL for buf, you'll get back DK_STAT_NORESOURCE.
 * If len is not big enough, you'll get back DK_STAT_NORESOURCE.
 */
DK_STAT dk_getsig(DK *dk, void *privatekey, unsigned char buf[], size_t len)
{
  if ((!dk)||(dk->dkmarker != DKMARK)||(!privatekey))
  {
    return DK_STAT_ARGS;
  }
  if (!buf)
  {
    return DKERR(DK_STAT_NORESOURCE);
  }
  switch (dk->signing)
  {
    case DK_SIGNING_SIGN:
    case DK_SIGNING_NOSIGN:
    {
      unsigned int siglen;
      unsigned char *sig;
      int size;
      BIO *bio, *b64;
      EVP_PKEY *pkey;

      bio = BIO_new_mem_buf(privatekey, -1);
      pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
      BIO_free(bio);

      if (!pkey)
      {
        /* their private key is no good TC33 */
        return DKERR(DK_STAT_BADKEY);
      }

      siglen = EVP_PKEY_size(pkey);
      sig = (unsigned char*) OPENSSL_malloc(siglen);
      EVP_SignFinal(&dk->mdctx, sig, &siglen, pkey);
      EVP_PKEY_free(pkey);

      bio = BIO_new(BIO_s_mem());
      if (!bio)
      {
        return DKERR(DK_STAT_NORESOURCE);
      }
      b64 = BIO_new(BIO_f_base64());
      if (!b64)
      {
        BIO_free(bio);
        return DKERR(DK_STAT_NORESOURCE);
      }
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
      BIO_push(b64, bio);
      if ((size_t)BIO_write(b64, sig, siglen) < siglen)
      {
        OPENSSL_free(sig);
        BIO_free_all(b64);
        return DKERR(DK_STAT_NORESOURCE);
      }
      BIO_flush(b64);
      OPENSSL_free(sig);

      size = BIO_read(bio, buf, len);
      BIO_free_all(b64);

      if ((size_t)size >= len)
      {
        return DKERR(DK_STAT_NORESOURCE); /* TC28 */
      }

      buf[size] = '\0';
      return DKERR(DK_STAT_OK);
    }
    case DK_SIGNING_VERIFY:
    case DK_SIGNING_NOVERIFY:
      return DKERR(DK_STAT_INTERNAL);
  }//end switch
  return DK_STAT_ARGS;
}


/* HEADER */
/*
 * Free all resources associated with this message.
 * dk is no longer usable.
 * if doClearErrState != 0, the OpenSSL ErrorState is freed.
 * Set clearErrState=0 if you use other openssl functions and
 * want to call openssl's ERR_remove_state(0) by yourself
 * ERR_remove_state(0) is declared in <openssl/err.h>
 */
DK_STAT dk_free(DK *dk, int doClearErrState)
{
  if ((!dk)||(dk->dkmarker != DKMARK))
  {
    return DK_STAT_ARGS;
  }
  if (dk->from)
  {
    DK_MFREE(dk->from);
  }
  if (dk->sender)
  {
    DK_MFREE(dk->sender);
  }
  if (dk->sender_beforesign)
  {
    DK_MFREE(dk->sender_beforesign);
  }
  if (dk->trace)
  {
    DK_MFREE(dk->trace);
  }
  if (dk->traceheader)
  {
    DK_MFREE(dk->trace);
  }
  if (dk->keyrec)
  {
    DK_MFREE(dk->keyrec);
  }
  if (dk->policyrec)
  {
    DK_MFREE(dk->policyrec);
  }
  if (dk->granularity)
  {
    DK_MFREE(dk->granularity);
  }
#ifdef DK_HASH_BUFF
  DK_MFREE(dk->hash_buff);
#endif
  EVP_MD_CTX_cleanup(&dk->mdctx);
  DK_MFREE(dk->header);   /* alloc'ing dk->header is not optional. */
  dk->dkmarker = ~DKMARK;
  DK_MFREE(dk);

  if (doClearErrState)
  {
     ERR_remove_state(0);
  }
  return DK_STAT_OK;
}

/* HEADER */
/*
 * return a pointer to a string which describes st.
 * The string is structured.  All the characters up to the first colon
 * contain the name of the DK_STAT constant.  From there to the end of
 * string is a human-readable description of the error.
 */
const char *DK_STAT_to_string(DK_STAT st)
{
  /* TC53 */
  if (st >= (sizeof errors) / (sizeof errors[0]))
  {
    return "DK_STAT_UNKNOWN: unknown status";
  }
  else
  {
    return errors[st];
  }
}


