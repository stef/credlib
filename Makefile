CREDLIB_VERS = 0.02

INSTALL_PATH = /usr/bin
MAN_INSTALL_PATH = /usr/share/man/man1
DOC_INSTALL_PATH = /usr/share/doc/hashcash-$(CREDLIB_VERS)

INSTALL = install
POD2MAN = pod2man
POD2HTML = pod2html
POD2TEXT = pod2text
DELETE = rm -f
LINK = ln -f
ETAGS = etags
MAKEDEPEND = makedepend
MSLIB = mslib

COPT_DEBUG = -g
COPT_GENERIC = -O3
COPT_GNU = -O3 -funroll-loops
COPT_X86 = -O3 -funroll-loops -march=i386 -mcpu=pentium -mmmx \
	-D_REENTRANT -D_THREAD_SAFE -fPIC
COPT_MINGW = -O3 -funroll-loops -march=i386 -mcpu=pentium -mmmx \
        -D_REENTRANT -D_THREAD_SAFE
COPT_G3_OSX = -O3 -funroll-loops -fno-inline -mcpu=750 -faltivec
COPT_PPC_LINUX = -O3 -funroll-loops -fno-inline -mcpu=604e -maltivec \
	-mabi=altivec

LIB=.a
EXES = chaum$(EXE) brands$(EXE)
LIBFLAGS = -L./ -lcred -lcrypto
CFLAGS = -g -Wall

LIBOBJS = libchaum.o libbrands.o credlib.o cexception.o


default: help generic

help:
	@echo "make <platform> where platform is:"
	@echo "    x86, mingw, mingw-dll, g3-osx, ppc-linux, gnu, generic, debug"
	@echo "other make targets are docs, install, clean, distclean, docclean"
	@echo ""
	@echo "(doing make generic by default)"
	@echo ""

build:	$(EXES) test

generic:
	$(MAKE) "CFLAGS=$(CFLAGS) $(REGEXP) $(COPT_GENERIC) $(COPT)" build

debug:
	$(MAKE) "CFLAGS=$(CFLAGS) $(REGEXP) $(COPT_DEBUG) $(COPT)" build

gnu:
	$(MAKE) "CFLAGS=$(CFLAGS) $(REGEXP) $(COPT_GNU) $(COPT)" "CC=gcc" build

x86: 
	$(MAKE) "CFLAGS=$(CFLAGS) $(REGEXP) $(COPT_X86) $(COPT)" build

g3-osx:
	$(MAKE) "CFLAGS=$(CFLAGS) $(REGEXP) $(COPT_G3_OSX) $(COPT)" build

ppc-linux:
	$(MAKE) "CFLAGS=$(CFLAGS) $(REGEXP) $(COPT_PPC_LINUX) $(COPT)" build

# mingw windows targets (cross compiler, or native)

mingw: 
	$(MAKE) "LIB=.lib" "CC=gcc" "EXE=.exe" "CFLAGS=$(COPT_MINGW) $(COPT)" "LDFLAGS=-L../../openssl-0.9.7b/ -lcrtdll -lgdi32 -lwsock32" "WINE=wine" build

test:
	$(WINE) ./chaum$(EXE) -tk 512
	$(WINE) ./brands$(EXE) -tk 512 -a3

chaum$(EXE):	chaum.o libcred$(LIB)
	$(CC) chaum.o -o $@ $(LIBFLAGS) $(LDFLAGS) 

brands$(EXE):	brands.o libcred$(LIB)
	$(CC) brands.o -o $@ $(LIBFLAGS) $(LDFLAGS) 

libcred$(LIB):	$(LIBOBJS)
	$(DELETE) $@
	$(AR) rcs $@ $(LIBOBJS)
	[ -e libcred.a ] || $(LINK) $@ libcred.a

cred.dll:	$(LIBOBJS)
	$(CC) -shared -o $@ $(LIBOBJS) \
		-Wl,--output-def,cred.def,--out-implib,libcred.a
	$(MSLIB) /machine:x86 /def:cred.def

libcred.so:	$(LIBOBJS) chaum brands
	$(CC) -shared -o $@ $(LIBOBJS) -lssl

chaum.1:	chaum.pod
	$(POD2MAN) -s 1 -c chaum -r $(CREDLIB_VERS) $? >$@

chaum.html:	chaum.pod
	$(POD2HTML) --title chaum $? > $@
	$(DELETE) pod2htm*

chaum.txt:	chaum.pod
	$(POD2TEXT) $? > $@

brands.1:	brands.pod
	$(POD2MAN) -s 1 -c brands -r $(CREDLIB_VERS) $? >$@

brands.html:	brands.pod
	$(POD2HTML) --title brands $? > $@
	$(DELETE) pod2htm*

brands.txt:	brands.pod
	$(POD2TEXT) $? > $@

depend:
	$(MAKEDEPEND) -- -Y *.c *.h

clean:
	$(DELETE) *.o *~

distclean:
	$(DELETE) *.o *.so *~ $(EXES) *.db *.bak TAGS core*
	$(DELETE) *.bak test/* *.dll *.lib *.exe *.a

tags:
	$(ETAGS) *.c *.h

# DO NOT DELETE

brands.o: brands.h credlib.h cexception.h types.h
chaum.o: chaum.h credlib.h cexception.h types.h
credlib.o: credlib.h cexception.h types.h
libbrands.o: brands.h credlib.h cexception.h types.h
libchaum.o: chaum.h credlib.h cexception.h types.h
brands.o: credlib.h cexception.h types.h
chaum.o: credlib.h cexception.h types.h
credlib.o: cexception.h types.h
