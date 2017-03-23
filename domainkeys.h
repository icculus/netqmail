/* This file is automatically created from the corresponding .c file */
/* Do not change this file; change the .c file instead. */
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

} DK_LIB;
/* STOPSTRUCT */

//UnixWare Fix -Tim
/* STARTSTRUCT */
typedef struct
{
} DK;
/* STOPSTRUCT */


/* returns the source file from which an error was returned. */
char * dk_errfile(DK *dk)
;


/* returns the source line number from which an error was returned. */
int dk_errline(DK *dk)
;


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
;


/* Per-process, one-time cleanup
 * Should be called just before the application ends.
 * the dklib pointer is not valid anymore after this call
 * This function should be called even if dk_init failed.
 * It's safe to call dk_shutdown with a NULL pointer
 */
void dk_shutdown(DK_LIB * dklib)
;


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
;


/* returns the int holding the options set
 * See dk_setopts for bit flags
 */
int dk_getopts(DK *dk)
;


/* DEPRECATED in favor of calling dk_setopts().
 * Enables character trace tracking
 *
 * use after dk_sign()/dk_verify()
 */
DK_STAT dk_enable_trace(DK *dk)
;


/* Prints trace table to *store variable (char string)
 * *dk is the container for the table
 * *store is a pointer to a character array to output to
 * store_size is the size of the character array *store
 *
 */
DK_STAT dk_get_trace(DK *dk, DK_TRACE_TYPE type, char *store, int store_size)
;


/* Prints difference trace table to *store variable (char string)
 * *dk is the container for the table
 * *store is a pointer to a character array to output to
 * store_size is the size of the character array *store
 * return DK_STAT_NOSIG if no DK-Trace header was found
 */
DK_STAT dk_compare_trace(DK *dk, DK_TRACE_TYPE type, char *store, int store_size)
;


/* Sets the DNS key/policy record manually (no DNS lookup)
 * txtrecord needs to be set to "e=perm;" to force a permanent DNS failure
 * txtrecord needs to be set to "e=temp;" to force a temporary DNS failure
 * Valid DK_TXT types are:
 * DK_TXT_KEY (normal selector record; for <selctor>._domainkey.<domain>)
 * DK_TXT_POLICY (domain policy record; for _domainkey.<domain>)
 */
DK_STAT dk_settxt(DK *dk, DK_TXT recordtype, const char *txtrecord)
;


/* Per-message, may be threaded.
 * canon is one of DK_CANON_*.
 * Returns state structure for operation.  Consult statp before using.
 */
DK *dk_sign(DK_LIB *dklib, DK_STAT *statp, int canon)
;


/* Per-message, may be threaded.
 * Returns state structure for operation.  Consult statp before using.
 */
DK *dk_verify(DK_LIB *dklib, DK_STAT *statp)
;


/* DEPRECATED in favor of calling dk_setopts()
 * set option to remove dupe headers
 * should be called after dk_sign();
 * any int NOT 0 turns dupe removal on
 */
DK_STAT dk_remdupe(DK *dk,int i)
;


/* Returns the policy flags belonging to the signing domain.
 * Sender: overrides From:, and the d= entry in the DK-Sig overrides both.
 * If the policy flags were not successfully fetched, DK_FLAG_SET will not
 * be set.
 */
DK_FLAGS dk_policy(DK *dk)
;


/* Copies the header names that were signed into the pointer.
 * Returns the number of bytes copied.
 * ptr may be NULL, in which case the bytes are just counted, not copied.
 * Feel free to call this twice; once to get the length, and again to
 * copy the data.
 * NOTE: If the return value is 0 then an error occured.
 *	It's a good idea to check for this
 */
int dk_headers(DK *dk, char *ptr)
;


/* Must NOT include dots inserted for SMTP encapsulation.
 * Must NOT include CRLF.CRLF which terminates the message.
 * Otherwise must be exactly that which is sent or received over the SMTP session.
 * May be called multiple times (not necessary to read an entire message into memory).
 */
DK_STAT dk_message(DK *dk, const unsigned char *ptr, size_t len)
;


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
;


/* Returns a pointer to the selector name used or NULL if there isn't one
 * Added by rjp
 */
const char *dk_selector(DK *dk)
;


/* Returns a pointer to the domain name used or NULL if there isn't one
 */
const char *dk_domain(DK *dk)
;


/*
 * Returns a pointer to a string which begins with "N", "S", or "F",
 * corresponding to None, Sender: and From:, respectively.
 * This single character is followed by a null-terminated RFC 2822 address.
 * The first character is "N" if no valid address has been seen yet,
 * "S" if the address came from the Sender: field, and "F" if the
 * address came from the From: field.
 */
char *dk_address(DK *dk)
;


/*
 * Returns a pointer to a null-terminated string containing the granularity
 * value found in the selector DNS record, if any, but only after dk_end
 * has been called. Otherwise returns NULL.
 */
char *dk_granularity(DK *dk)
;


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
;


/*
 * DEPRECATED in favor of calling dk_end and dk_policy() directly.
 * If you pass in NULL for dkf, the policy flags will not be fetched.
 * If the message verified okay, the policy flags will not be fetched.
 */
DK_STAT dk_eom(DK *dk, DK_FLAGS *dkf)
;


/*
 *
 * privatekey is the private key used to create the signature; It should contain
 * the entire contents of a PEM-format private key file, thusly it will begin with
 * -----BEGIN RSA PRIVATE KEY-----.  It should be null-terminated.
 */
size_t dk_siglen(void *privatekey)
;


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
;


/*
 * Free all resources associated with this message.
 * dk is no longer usable.
 * if doClearErrState != 0, the OpenSSL ErrorState is freed.
 * Set clearErrState=0 if you use other openssl functions and
 * want to call openssl's ERR_remove_state(0) by yourself
 * ERR_remove_state(0) is declared in <openssl/err.h>
 */
DK_STAT dk_free(DK *dk, int doClearErrState)
;


/*
 * return a pointer to a string which describes st.
 * The string is structured.  All the characters up to the first colon
 * contain the name of the DK_STAT constant.  From there to the end of
 * string is a human-readable description of the error.
 */
const char *DK_STAT_to_string(DK_STAT st)
;


