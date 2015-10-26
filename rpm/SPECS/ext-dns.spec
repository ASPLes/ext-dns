%define release_date %(date +"%a %b %d %Y")
%define ext_dns_version %(cat VERSION)

Name:           ext-dns
Version:        %{ext_dns_version}
Release:        5%{?dist}
Summary:        A toolkit to buld DNS servers
Group:          System Environment/Libraries
License:        GPLv2+ 
URL:            http://www.aspl.es/ext-dns
Source:         %{name}-%{version}.tar.gz


%define debug_package %{nil}

%description 
ext-Dns is a software solution, written by ASPL (Advanced Software
Production Line, S.L.), that is composed by a core library, an
extensible forward dns server and some additional tools designed to
create DNS server solutions that are able to do any additional
operation at the resolution level (running commands, rewriting
replies, gathering stats and so on), without any limit.

%prep
%setup -q

%build
PKG_CONFIG_PATH=/usr/lib/pkgconfig:/usr/local/lib/pkgconfig %configure --prefix=/usr --sysconfdir=/etc
make clean
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot} INSTALL='install -p'
find %{buildroot} -name '*.la' -exec rm -f {} ';'
mkdir -p %{buildroot}/etc/init.d
install -p %{_builddir}/%{name}-%{version}/doc/ext-dnsd-rpm-init.d %{buildroot}/etc/init.d/ext-dnsd

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

# %files -f %{name}.lang
%doc AUTHORS COPYING NEWS README THANKS
# %{_libdir}/libaxl.so.*

# %files devel
# %doc COPYING
# %{_includedir}/axl*
# %{_libdir}/libaxl.so
# %{_libdir}/pkgconfig/axl.pc

# libext-dns package
%package -n libext-dns
Summary: ext-Dns base core library for DNS solutions
Group: System Environment/Libraries
Requires: libaxl1
%description  -n libext-dns
libext-dns is the core base library that will allow you to
build DNS servers easily.
%files -n libext-dns
   /usr/lib64/libext-dns.a
   /usr/lib64/libext-dns.so
   /usr/lib64/libext-dns.so.0
   /usr/lib64/libext-dns.so.0.0.0

# libext-dns-dev package
%package -n libext-dns-dev
Summary: ext-Dns base core library for DNS solutions (dev)
Group: System Environment/Libraries
Requires: libaxl-dev
Requires: libext-dns
%description  -n libext-dns-dev
Development headers required to create DNS solutions based
on libext-dns
%files -n libext-dns-dev
   /usr/include/ext-dns/ext-dns-cache.h
   /usr/include/ext-dns/ext-dns-ctx.h
   /usr/include/ext-dns/ext-dns-errno.h
   /usr/include/ext-dns/ext-dns-handlers.h
   /usr/include/ext-dns/ext-dns-io.h
   /usr/include/ext-dns/ext-dns-message.h
   /usr/include/ext-dns/ext-dns-private.h
   /usr/include/ext-dns/ext-dns-reader.h
   /usr/include/ext-dns/ext-dns-session.h
   /usr/include/ext-dns/ext-dns-support.h
   /usr/include/ext-dns/ext-dns-thread-pool.h
   /usr/include/ext-dns/ext-dns-thread.h
   /usr/include/ext-dns/ext-dns-types.h
   /usr/include/ext-dns/ext-dns.h
   /usr/lib64/pkgconfig/ext-dns.pc

# ext-dnsd package
%package -n ext-dnsd
Summary: ready to use forward dns server built on top libext-dns
Group: System Environment/Libraries
Requires: libaxl1
Requires: libext-dns
Requires: ext-dns-query
%description  -n ext-dnsd
ext-dnsd is a forward DNS server that can be used to control and
track which DNS requests are allowed.
%files -n ext-dnsd
   /etc/cron.d/ext-dnsd-watcher
   /etc/ext-dns/ext-dns.example.conf
   /usr/bin/ext-dnsd
   /etc/init.d/ext-dnsd
   /usr/bin/ext-dns-watcher.py
%post -n ext-dnsd
chkconfig ext-dnsd on
if [ ! -f /etc/ext-dns/ext-dns.conf ]; then
       cp /etc/ext-dns/ext-dns.example.conf /etc/ext-dns/ext-dns.conf
fi
service ext-dnsd restart

# ext-dns-query package
%package -n ext-dns-query
Summary: client DNS query tool with host like output
Group: System Environment/Libraries
Requires: libext-dns
%description  -n ext-dns-query
edq (ext-dns-query) tool is a command client tool that allows
doing DNS query operations providing a host like output and
a similar invocation. It includes additional options not available
on host tool.
%files -n ext-dns-query
   /usr/bin/edq


%changelog
%include rpm/SPECS/changelog.inc


