#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* This program creates headers by parsing a .c file looking for magic
 * comments.  It copies everything from STARTHEAD through STOPHEAD to
 * the header file.  Then it excludes everything between STARTPRIV and
 * STOPPRIV.  When it sees a HEADER comment, it copies everything from
 * there to the first line with a open brace, and appends a semicolon.
 * 
 * There is no point in maintaining the same information in two files.
 * Better to generate the header from the source itself.
 */

int printing = 0;
char line[1024]; /* domainkey.c doesn't have any lines longer than 1024, so enuf. */
int linelen;
int getstruct = 0;
#define startswith(a,b) (!strncmp((a),(b),strlen(b)))

#ifdef _MSC_VER
#define UNIXWARE 1
int main(int argc, char** argv)
{   
   if ((argc <= 1) || strcmp(argv[1], "def"))
   {
#else
int main()
{
#endif
      printf("/* This file is automatically created from the corresponding .c file */\n");
      printf("/* Do not change this file; change the .c file instead. */\n");

      while (fgets(line, sizeof(line), stdin)) {
         if (line[strlen(line)-1] != '\n') {
            fprintf(stderr, "oops, 'line' is too short\n");
            exit(1);
         }
    //unixware fix to keep structs in .h -Tim
    #ifdef UNIXWARE
    if (startswith(line, "/* STARTSTRUCT") && (getstruct == 0))
    {
      getstruct = 1;
      continue;
    }
    
    if (getstruct == 1)
    {
      if (startswith(line, "/* STOPSTRUCT"))
      {
        getstruct = 0;
      }
      else
      {
        fputs(line, stdout);
      }
      continue;
    }    
    #endif
         if (startswith(line, "/* STARTHEAD") || startswith(line, "/* STOPPRIV")) {
            printing = 1;
         } else if (startswith(line, "/* STOPHEAD") || startswith(line, "/* STARTPRIV")) {
            printing = 0;
         } else if (startswith(line, "/* HEADER")) {
            printing = 2;
         } else if (printing == 2 && startswith(line, "{")) {
            printf(";\n\n\n");
            printing = 0;
         } else if (printing) {
            fputs(line, stdout);
         }
      }
#ifdef _MSC_VER
   }
   else
   {
      printf("; This file is automatically created from the corresponding .c file\n");
      printf("; Do not change this file; change the .c file instead.\n\n");
      printf("EXPORTS\n");

      while (fgets(line, sizeof(line), stdin)) {
         if (line[strlen(line)-1] != '\n') {
            fprintf(stderr, "oops, 'line' is too short\n");
            exit(1);
         }
         if (startswith(line, "/* HEADER")) {
            printing = 1;
         } else if ((printing == 1) && startswith(line, " */")) {            
            printing = 2;
         } else if (printing == 2) {
            char * tok = strtok(line, " *(");
            if (!strcmp(tok, "const"))
               tok = strtok(NULL, " *(");
            tok = strtok(NULL, " *(");
            printf("\t%s\n", tok);
            printing = 0;
         }
      }
   }
#endif
   exit(0);
}
