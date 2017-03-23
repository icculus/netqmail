#include <stdio.h>
#include <string.h>
#include <domainkeys.h>
#include <unistd.h>
#include <stdlib.h>

int optf = 0;

int errorout(DK *dk,DK_STAT st) {
  if (optf && dk) fprintf(stderr, "%s(%d):",dk_errfile(dk),dk_errline(dk));
  fprintf(stderr, "dktest: %s\n", DK_STAT_to_string(st));
  exit(1);
}

int main(int argc, char *argv[]) {
  char inbuf[1024];
  size_t inlen;
  char advice[2048];
  size_t advicelen = sizeof(advice);
  DK *dk;
  DK_LIB *dklib;
  char trace_count[BUFSIZ];

  DK_STAT st,dkt_st;
  signed char ch;
  int opts=0, optv=0, optt=0, opth=0,optr=0, optT = 0,optc=DK_CANON_SIMPLE;

  int local_term = -1, i = 0;
  char *inp;
  char *start;

  char *canon = "simple";
  char *keyfn = NULL;
  char *selector = NULL;
  char privkey[2048];
  FILE *privkeyf = NULL;
  size_t privkeylen;
  DK_FLAGS dkf = 0;

  DK_TRACE_TYPE dk_trace_tag[4] =
  {
    DKT_RAW_HEADER,
    DKT_CANON_HEADER,
    DKT_RAW_BODY,
    DKT_CANON_BODY
  };

  while (1) {
    ch = getopt(argc, argv,"s:vt:fb:c:hrT");
    if (ch == -1) break;
    switch (ch) {
    case 'T':
      optT = 1;
      break;
    case 'v':
      optv = 1;
      break;
    case 'f':
      optf = 1;
      break;
    case 'r':
      optr = 1;
      opth = 1;
      break;
    case 's':
      opts = 1;
      keyfn = optarg;
      selector = optarg;
      while (*optarg) {
	if (*optarg == '/')
	  selector = optarg+1;
	optarg++;
      }
      break;
    case 't':
      optt = atoi(optarg);
      break;
    case 'h':
    	opth = 1;
    	break;
    case 'b':
      advicelen = atoi(optarg);
      if (advicelen > sizeof(advice)) advicelen = sizeof(advice);
      break;
    case 'c':
      if (!strcmp(optarg, "simple")) optc = DK_CANON_SIMPLE, canon = "simple";
      else if (!strcmp(optarg, "nofws")) optc = DK_CANON_NOFWS, canon = "nofws";
      else {
	fprintf(stderr, "dktest: unrecognized canonicalization.\n");
	exit(1);
      }
    }
  }

  if (opts) {
    privkeyf = fopen(keyfn, "r");
    if (!privkeyf) { /*TC10*/
      fprintf(stderr, "dktest: can't open private key file %s\n", keyfn);
      exit(1);
    }
    privkeylen = fread(privkey, 1, sizeof(privkey), privkeyf);
    if (privkeylen == sizeof(privkey)) { /* TC9 */
      fprintf(stderr, "dktest: private key buffer isn't big enough, use a smaller private key or recompile.\n");
      exit(1);
    }
    privkey[privkeylen] = '\0';
    fclose(privkeyf);
  }

  if (optt == 1) errorout(NULL,0); /*TC2*/
  if (optt == 2) errorout(NULL,32767); /*TC3*/

  dklib = dk_init(&st);
  if (st != DK_STAT_OK) errorout(NULL,st);
  if (!dklib) errorout(NULL, 200);

  if (optv)
  {
    dk = dk_verify(dklib, &st);
    if (st != DK_STAT_OK)
      errorout(dk,st);
  }
  else if (opts)
  {
    dk = dk_sign(dklib, &st, optc);
    if (st != DK_STAT_OK)
      errorout(dk,st);
    if (optr)
      st = dk_setopts(dk,DKOPT_RDUPE);
    if (st != DK_STAT_OK)
      errorout(dk,st);
  }
  else
  {
    fprintf(stderr, "dktest: [-f] [-b#] [-c nofws|simple] [-v|-s selector] [-h] [-t#] [-r] [-T]\n"); /* TC1 */
    exit(1);
  }
  if (optT)//trace
	{
 	  //(DKOPT_TRACE_h|DKOPT_TRACE_H|DKOPT_TRACE_b|DKOPT_TRACE_B)
	  st = dk_setopts(dk,(DKOPT_TRACE_h|DKOPT_TRACE_H|DKOPT_TRACE_b|DKOPT_TRACE_B));
	  if (st != DK_STAT_OK)
	    errorout(dk,st);
	}

  if (optt == 3) errorout(dk,dk_message(NULL, "", 1)); /* TC4 */
  if (optt == 4) errorout(dk,dk_message(dk, NULL, 1)); /* TC5 */
  if (optt == 5) errorout(dk,dk_message(dk, "", 0)); /* TC6 */
  if (optt >= 100 && optt <= 140)
    errorout(dk,optt-100); /* TC53 */

  st = DK_STAT_OK;

 /* This should work with DOS or UNIX text files -Tim
 * Reduced calls to dk_message, in lib dkhash called for EVERY char
 * DOS formatted input (CRLF line terminated) will have fewer calls
 * to dk_message() than UNIX (LF line terminated) input.
 */
  while (1)
  {
    inlen = fread(inbuf, 1, sizeof(inbuf), stdin);
    inp = inbuf;
    start = inbuf;
    i = 0;
    //check if local line term is CRLF(DOS) or LF(UNIX,default)
    //Anything else will probably not work correctly. -Tim
    if (local_term == -1)
    {
      char *lf = NULL;
      if ((lf = strchr(inbuf, (int)'\n')) != NULL)
      {//if no newline is found assume UNIX, until we find one
        if ((lf != inp ) && (*(--lf) == '\r'))
          local_term = 1;
        else
          local_term = 0;
      }
    }
    if (local_term > 0) //CRLF already
    {
      if (st==DK_STAT_OK)
        st = dk_message(dk,inp,inlen);
      if (inlen < sizeof(inbuf))
        break;
      else
        continue;
    }
    while (inlen--)
    {
      if (*inp == '\n')
      {
	      if (st==DK_STAT_OK && i)
	      {
	        st = dk_message(dk, start, i);
	        i = 0;
        }
        inp++;
	      start = inp;
	      if (st==DK_STAT_OK)
	        st = dk_message(dk, "\r\n", 2);
      }
      else
      {
        inp++;
        i++;
      }
      if (st != DK_STAT_OK)
        break;  //stop looping if there was an error
    }
    if (st==DK_STAT_OK && i)
      st = dk_message(dk, start, i);

    if ((inp-inbuf < sizeof(inbuf)) || (st != DK_STAT_OK))
      break; //if we read in the entire message or encountered an error
  }


  if (st==DK_STAT_OK) {
    if (optt == 10) st = dk_end(dk, &dkf);
    else            st = dk_eom(dk, &dkf);
  }
  if (optT)
  {
    printf("DomainKey-Trace: U=http://domainkeys.sourceforge.net; V=TESTING;\n");
    for (i = 0; i < 4; i++)
    {
      if (dk_get_trace(dk,dk_trace_tag[i],trace_count,sizeof(trace_count)) != DK_STAT_OK)
      {
        fprintf(stderr,"dktest: Not enough resources for trace buffer output\n");
        break;
      }
      else
      {
      	printf("  %s\n",trace_count);
      }
    }
    if (optv)
    {
    	printf("DomainKey-Trace-Diff:\n");

    	for (i = 0; i < 4; i++)
    	{
    	  dkt_st = dk_compare_trace(dk,dk_trace_tag[i],trace_count,sizeof(trace_count));
        if (dkt_st == DK_STAT_NOSIG)
        {
          printf("  No DK-Trace: header found\n");
          break;
        }
        else if (dkt_st != DK_STAT_OK)
        {
          fprintf(stderr,"dktest: Not enough resources for trace buffer output\n");
          break;
	      }
	      else
	        printf("  %s\n",trace_count);
      }
    }
  }


  if ((optt == 6 || optt == 10) && optv) {
    printf("flags: ");
    if (dkf & DK_FLAG_SET) printf("+");
    if (dkf & DK_FLAG_TESTING) printf("t");
    if (dkf & DK_FLAG_SIGNSALL) printf("s");//wont be set if dk_end() is sucessful
    if (dkf & DK_FLAG_G) printf("g");
    printf("\n");
  } else if (optt == 6 && opts) {
    errorout(dk, dk_getsig(dk, NULL, NULL, advicelen)); /* TC14 */
  } else if (optt == 7) {
    char *from = dk_from(dk);

    if (!from) from = "";
    printf("%s\n",from);	/* TC14-1, TC14-2 */
  } else if (optt == 11) {
    char *from = dk_address(dk);

    printf("%s\n",from);	/* TC14-3, TC14-4 */
  } else if (optt == 9) {
    char *s;

    s = malloc(dk_headers(dk, NULL));
    dk_headers(dk, s);
    printf("%s\n",s);
    free(s);
  } else if (optt == 8 && opts) {
    dk_getsig(dk, privkey, advice, advicelen);
    if (st != DK_STAT_OK) errorout(dk,st);
    printf("%d %d\n",dk_siglen(privkey), strlen(advice)); /* TC39 */
  } else if (opts) {
    if (st != DK_STAT_OK) errorout(dk,st);
    st = dk_getsig(dk, privkey, advice, advicelen);
    if (st != DK_STAT_OK) errorout(dk,st);
    printf("Comment: DomainKeys? See http://domainkeys.sourceforge.net/\n"
	   "DomainKey-Signature: a=rsa-sha1; q=dns; c=%s;\n"
	   "  s=%s; d=%s;\n"
	   "  b=%s;\n", canon, selector, dk_from(dk), advice);
	if (opth == 1)
	{
		if (dk_headers(dk,NULL) < sizeof(inbuf))
		{
			dk_headers(dk,inbuf);
			printf("  h=%s;\n",inbuf);
		}
	}
  } else if (optv) {
    char *status = NULL;

    switch(st) {
    case DK_STAT_OK: status = "good"; break;
    case DK_STAT_BADSIG: status = "bad"; break;
    case DK_STAT_NOSIG: status = "no signature"; break;
    case DK_STAT_NOKEY:
    case DK_STAT_CANTVRFY: status = "no key"; break;
    case DK_STAT_BADKEY: status = "bad key"; break;
    case DK_STAT_INTERNAL:
    case DK_STAT_ARGS:
    case DK_STAT_SYNTAX: status = "bad format"; break;
    case DK_STAT_NORESOURCE: status = "no resources"; break;
    case DK_STAT_REVOKED: status = "revoked"; break;
	case DK_STAT_GRANULARITY: status = "bad sender (g=)"; break;
    }
    printf("Comment: DomainKeys? See http://domainkeys.sourceforge.net/\n"
	   "DomainKey-Status: %s\n", status);
    rewind(stdin);
  }
  if (st != DK_STAT_OK) errorout(dk,st);

  dk_free(dk,1);//cleanup properly (not really necessary for single run process)
  dk_shutdown(dklib);
  return 0;
}
