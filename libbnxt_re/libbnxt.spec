Name	: libbnxt_re
Version	: 233.2.77.9
Release	: _PARAM_RELEASE%{?dist}
Summary	: Userspace Library for Broadcom ROCE Device.
Group	: System Environment/Libraries
License	: GPL/BSD
Vendor	: Broadcom Limited
URL	: http://www.broadcom.com
Source	: libbnxt_re-233.2.77.9.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: libibverbs-devel

%description
libbnxt_re provides a device-specific userspace driver for Broadcom Netxtreme RoCE Adapters
for use with the libibverbs library.

%if %{defined suse_version}
%debug_package
%endif

%package devel
Summary: Development files for the libbnxt_re driver
Group: System Environment/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
Static version of libbnxt_re that may be linked directly to an
application, which may be useful for debugging.

%prep
%setup -q -n %{name}-%{version}

%build
./autogen.sh
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall
# remove unpackaged files from the buildroot
rm -f $RPM_BUILD_ROOT%{_libdir}/*.la

%post
# If libbnxt_re is inboxed
if [ -f "%{_libdir}/libibverbs/libbnxt_re-rdmav"*".so" ];then
   #to get full name and path
   libbnxtre=$(ls "%{_libdir}/libibverbs/libbnxt_re-rdmav"*".so")
   libbnxtre_mod=$(echo $libbnxtre | sed "s/libbnxt_re-/old.libbnxt_re-/")
   mv $libbnxtre $libbnxtre_mod > /dev/null 2>&1
fi
/sbin/ldconfig

%postun
# Undo the change if we are doing a complete uninstall and had renamed the file
if [ $1 -eq 0 ] && [ -f "%{_libdir}/libibverbs/old.libbnxt_re-rdmav"*".so" ]; then
   libbnxtre_mod=$(ls "%{_libdir}/libibverbs/old.libbnxt_re-rdmav"*".so")
   libbnxtre=$(echo $libbnxtre_mod | sed "s/old.//")
   mv $libbnxtre_mod $libbnxtre > /dev/null 2>&1
fi
/sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/libbnxt_re*.so
#%doc AUTHORS COPYING ChangeLog README
%config %{_sysconfdir}/libibverbs.d/bnxt_re.driver

%files devel
%defattr(-,root,root,-)
%{_libdir}/libbnxt_re*.a

%changelog
