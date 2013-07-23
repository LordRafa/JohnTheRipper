#!/bin/bash

if [ $1 = "clean" ]; then

  make $1
  cd cgminer; make distclean; rm ../../run/cgminer; rm ../../run/*.cl; cd ..
  cd dtach; make distclean; rm ../../run/dtach
  echo "all ok" && exit 0

else

  if [ `uname -m` = "x86_64" ]; then
    LDFLAGS="-L/opt/AMDAPP/lib/x86_64/"
  else
    LDFLAGS="-L/opt/AMDAPP/lib/x86"
  fi

  make $1 && \
  CFLAGS="-O2 -Wall -march=native -I/opt/AMDAPP/include/" && \
  cd cgminer && ./configure --enable-cpumining --enable-scrypt --without-curses && make && mv cgminer ../../run && cp *.cl ../../run && cd .. && \
  cd dtach && ./configure && make && mv dtach ../../run/  && \
  echo "all ok" && exit 0

fi

echo "error"
exit 1
