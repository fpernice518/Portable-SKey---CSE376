#include "config.h"
#include "skey.h"

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#else
#  error Must have stdio.h
#endif



void debuginfo(char* lvlOne, char* lvlTwo, char* lvlThree)
{
  switch(debugLvl)
  {
    case 3:
      fprintf(logger, lvlThree);
    case 2:
      fprintf(logger, lvlTwo);
    case 1:
      fprintf(logger, lvlOne);
  }
}
