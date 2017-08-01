#============================================================================================
# variable definitions and headers
#============================================================================================

CONFIG_HRD="config.h"

VERSION_NUMBER=1.0

MYHEADERS="assert.h crypt.h ctype.h ctype.h errno.h errno.h fcntl.h features.h grp.h pwd.h
           sgtty.h shadow.h signal.h stdio.h stdlib.h string.h sys/param.h 
           sys/quota.h sys/resource.h sys/resource.h sys/stat.h sys/stat.h sys/systeminfo.h
           sys/time.h sys/types.h termios.h time.h unistd.h"

ENDIAN=`printf '\1' | od -dAn`

#============================================================================================
# test for valid number of args
#============================================================================================

if [[ $# -eq 0 ]] || [[ $# -eq 2 ]] || [[ $# -gt 3 ]]; then
  echo Invalid number of arguments
  exit
fi

#============================================================================================
# remove old header and create new file, copy makefile for later
#============================================================================================

rm $CONFIG_HRD                                
touch $CONFIG_HRD                             
cp Makefile.tmpl Makefile

#============================================================================================
# add guardian to prevent multiple inclusion
#============================================================================================

echo "#ifndef CONFIG_H" >> $CONFIG_HRD
echo "#define CONFIG_H" >> $CONFIG_HRD
echo

#============================================================================================
# append a version number to the file
#============================================================================================

echo "#define VERSION_NUMBER $VERSION_NUMBER" >> $CONFIG_HRD 

#============================================================================================
# detect endianess of the system and append it to the config file
#============================================================================================

# using MY_LITTLE/BIG_ENDIAN because LITTLE/BIG_ENDIAN are pre-defined on some systems
if [ "$ENDIAN" -eq "1" ]; then
	echo "#define MY_LITTLE_ENDIAN" >> $CONFIG_HRD
  echo "TYPE: LITTLE ENDIAN"
else
	echo "#define MY_BIG_ENDIAN" >> $CONFIG_HRD
  echo "TYPE: BIG ENDIAN"
fi

#============================================================================================
# search for the system headers
#============================================================================================

for hdr in $MYHEADERS ; do
  if test -f /usr/include/$hdr ; then
	  echo FOUND: $hdr
	  # add #define to config.h
	  tmp=`echo $hdr | tr 'abcdefghijklmnopqrstuvwxyz/.' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ__'`
	  echo "#define HAVE_$tmp" >> config.h
  else
	  echo NOT FOUND: $hdr
  fi
done
#============================================================================================
# get compiler from args or choose default CC
#============================================================================================

if [[ $1 = "-C" ]] || [[ $1 = "-c" ]]; then
    MYCC=$2
else
    MYCC=cc
fi

echo Using compiler $MYCC

#============================================================================================
# test the compiler
#============================================================================================

echo 'main(){}' > test.c
$MYCC test.c
./a.out >/dev/null
if [[ $? -eq 0 ]]; then
    echo CC succeeded
    MYCC=cc
else
    echo $MYCC failed, testing gcc
    MYCC=gcc
    $MYCC test.c
    ./a.out >/dev/null
    if [[ $? -eq 0 ]]; then
      echo Cannot find a good compiler
      rm test.c a.out >/dev/null
      exit
    else
      echo GCC was successful
      rm test.c a.out >/dev/null
    fi
fi

#============================================================================================
# test for crypt.h linkage
#============================================================================================

test -f /usr/include/crypt.h
cat << EOF > test.c
#include <crypt.h>
main() {crypt("hello", "world");}
EOF

$MYCC test.c >/dev/null
if [[ $? -eq 0 ]]; then
  LFLAGS=""
else
  LFLAGS="-lcrypt"
fi
rm test.c a.out

sed "s:&LFLAGS&:$LFLAGS:g" < Makefile.tmpl > Makefile

#============================================================================================
# end guardian
#============================================================================================

echo
echo "#endif /* CONFIG_H */" >> $CONFIG_HRD


#============================================================================================
# perform sed's on the makefile template
#============================================================================================

sed "s:&CC&:$MYCC:g" < Makefile > Makefile.tmp

if [[ $# -eq 1 ]]; then
  sed "s:&BIN&:$1:g" < Makefile.tmp > Makefile
  INLPATH=$1
else
  sed "s:&BIN&:$3:g" < Makefile.tmp > Makefile
  INLPATH=$3
fi

#============================================================================================
# make install directory and make the target
#============================================================================================
mkdir -p $INLPATH/lib

rm Makefile.tmp >/dev/null

make target
