lib_LTLIBRARIES = src/@BNXTLIBNAME@.la

AM_CFLAGS = -Wall -D_GNU_SOURCE @RDMA_CORE_HEADERS@

# Disable GCC 9 warning about pointers to members of a packed struct
AM_CFLAGS += -Wno-address-of-packed-member

if HAVE_LD_VERSION_SCRIPT
    bnxtre_version_script = -Wl,--version-script=$(srcdir)/src/bnxt_re.map
else
    bnxtre_version_script =
endif

src_@BNXTLIBNAME@_la_SOURCES = src/main.c src/verbs.c src/memory.c src/db.c		\
			       src/bnxt_re_dv.c
if HAVE_ROCELIB_TEST_SUITE
src_@BNXTLIBNAME@_la_SOURCES += src/debug.c
endif
src_@BNXTLIBNAME@_la_LDFLAGS = -avoid-version -module -release				\
				@IBV_DEVICE_LIBRARY_EXTENSION@ $(bnxtre_version_script)

bnxtreconfdir = $(sysconfdir)/libibverbs.d
bnxtreconf_DATA = @DRVFILENAME@.driver
drvname = @DRVFILENAME@.driver

EXTRA_DIST = src/bnxt_re.map src/main.h src/abi.h src/memory.h src/verbs.h		\
	     src/list.h src/version.h src/compat.h src/bnxt_re_dv.h 			\
	     src/rc-compat src/bnxt_re_dv_internal.h src/bnxt_re_hsi.h					\
	     ChangeLog libbnxt.spec.in $(drvname) autogen.sh README.TXT RELEASE.TXT

ACLOCAL_AMFLAGS= -I m4

LIBS=-lm @LIBS@

dist-hook: libbnxt.spec
	cp libbnxt.spec $(distdir)

HDR_DIR=/usr/include/infiniband/

install-exec-hook:
	@if [ ! -h `ls $(DESTDIR)$(libdir)/@BNXTLIBNAME@-*.so|head -1` ] ;		\
	then										\
		if ! test -d $(HDR_DIR); then						\
			mkdir $(HDR_DIR);						\
		fi;									\
		cp -f src/bnxt_re_dv.h $(HDR_DIR);					\
		cp -f src/bnxt_re_hsi.h $(HDR_DIR);					\
		cd $(DESTDIR)$(libdir);							\
		$(LN_S) -f @BNXTLIBNAME@.so @BNXTLIBNAME@-$(VERSION).so;		\
		echo "Installed @BNXTLIBNAME@ version $(VERSION)";			\
		cd -;									\
	else										\
		if ! test -d $(HDR_DIR); then						\
			mkdir $(HDR_DIR);						\
		fi;									\
		cp -f src/bnxt_re_dv.h $(HDR_DIR);					\
		cp -f src/bnxt_re_hsi.h $(HDR_DIR);					\
		cd $(DESTDIR)$(libdir);							\
		rm -f @BNXTLIBNAME@-[0-9]*.so;						\
		$(LN_S) -f @BNXTLIBNAME@.so @BNXTLIBNAME@-$(VERSION).so;                \
		cd -;									\
		echo "Updated @BNXTLIBNAME@ version to $(VERSION)";			\
	fi

uninstall-hook:
	@if [ -h `ls $(DESTDIR)$(libdir)/@BNXTLIBNAME@-*.so|head -1` ] ;		\
	then										\
		/bin/rm -f $(DESTDIR)$(libdir)/@BNXTLIBNAME@-*.so;			\
		echo "Removed @BNXTLIBNAME@ version $(VERSION)";			\
		rm -rf $(HDR_DIR)/bnxt_re_dv.h;						\
		rm -rf $(HDR_DIR)/bnxt_re_hsi.h;						\
	fi
