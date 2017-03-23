/* This was originally http://netsounds.eresmas.net/spfquery/spfquery.c,
 * but it isn't anymore. */

// added by nhatier for compilation under MSVC
#ifdef _MSC_VER
#include <windows.h>
#include <windns.h>
#include <openssl/evp.h>
#else //end added by nhatier
#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#endif

extern char *dk_strdup(const char *s);

static unsigned short getshort(unsigned char *cp) {
  return (cp[0] << 8) | cp[1];
}

/* we always return a null-terminated string which has been malloc'ed.  The string
 * is always in the tag=value form.  If a temporary or permanent error occurs,
 * the string will be exactly "e=perm;" or "e=temp;".
 * Note that it never returns NULL.
 */
char *dns_text(char *dn)
{
// added by nhatier for compilation under MSVC
#ifdef _MSC_VER
   DNS_RECORD * l_Records = NULL;
   DNS_STATUS l_Result = DnsQuery(dn, DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &l_Records, NULL);
   if (l_Result == ERROR_SUCCESS)
   {
      if (l_Records->wType == DNS_TYPE_TEXT)
      {
         unsigned int i;
         char buf[4096];
         buf[0] = 0;
         for (i = 0; i < l_Records->Data.TXT.dwStringCount; i++)
         {
            strcat(buf, l_Records->Data.TXT.pStringArray[i]);
         }
         DnsRecordListFree(l_Records, DnsFreeRecordList);
         return dk_strdup(buf);
      }
      else
      {
         DnsRecordListFree(l_Records, DnsFreeRecordList);
         return dk_strdup("e=perm;");
      }
   }
   else if (l_Result == DNS_ERROR_RECORD_TIMED_OUT)
   {
      DnsRecordListFree(l_Records, DnsFreeRecordList);
      return dk_strdup("e=temp;");
   }
   else
   {
      DnsRecordListFree(l_Records, DnsFreeRecordList);
      return dk_strdup("e=perm;");
   }
#else //end added by nhatier
    u_char response[PACKETSZ+1]; /* response */
    int responselen;		/* buffer length */

    int i, rc;			/* misc variables */
    int ancount, qdcount;	/* answer count and query count */
    u_short type, rdlength;		/* fields of records returned */
    u_char *eom, *cp;

    u_char buf[PACKETSZ+1];	/* we're storing a TXT record here, not just a DNAME */
    u_char *bufptr;

    responselen = res_query(dn, C_IN, T_TXT, response, sizeof(response));
    if (responselen  < 0){
      if (h_errno == TRY_AGAIN) return dk_strdup("e=temp;");
      else return dk_strdup("e=perm;");
    }

    qdcount = getshort( response + 4); /* http://crynwr.com/rfc1035/rfc1035.html#4.1.1. */
    ancount = getshort( response + 6);

    eom = response + responselen;
    cp  = response + HFIXEDSZ;

    while( qdcount-- > 0 && cp < eom ) {
      rc = dn_expand( response, eom, cp, (char *)buf, MAXDNAME );
      if( rc < 0 ) {
	return dk_strdup("e=perm;");
      }
      cp += rc + QFIXEDSZ;
    }

    while( ancount-- > 0 && cp < eom ) {
      rc = dn_expand( response, eom, cp, (char *)buf, MAXDNAME );
      if( rc < 0 ) {
	return dk_strdup("e=perm;");
      }

      cp += rc;

      if (cp + RRFIXEDSZ >= eom) return dk_strdup("e=perm;");

      type = getshort(cp + 0); /* http://crynwr.com/rfc1035/rfc1035.html#4.1.3. */
      rdlength = getshort(cp + 8);
      cp += RRFIXEDSZ;

      if( type != T_TXT ) {
	cp += rdlength;
	continue;
      }

      bufptr = buf;
      while (rdlength && cp < eom) {
	int cnt;

	cnt = *cp++;		 /* http://crynwr.com/rfc1035/rfc1035.html#3.3.14. */
	if( bufptr-buf + cnt + 1 >= PACKETSZ )
	  return dk_strdup("e=perm;");
	if (cp + cnt > eom)
	  return dk_strdup("e=perm;");
	memcpy( bufptr, cp, cnt);
	rdlength -= cnt + 1;
	bufptr += cnt;
	cp += cnt;
	*bufptr = '\0';
      }

      return (char *) dk_strdup( buf );
    }
    return dk_strdup("e=perm;");
#endif
}
