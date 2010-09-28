Name: cyfer
Summary: A low-level cryptographic library
Version: 0.6.1
Release: 1
Copyright: BSD
Group: Development/Libraries
Vendor: Senko Rasic
Source: cyfer-0.6.1.tar.gz
Packager: Senko Rasic <senko@senko.net>
URL: http://senko.net/
BuildRoot: /tmp/cyfer-0.6.0-rpm-build
Provides: libcyfer-0.6.0.so
Requires: ld-linux.so.2 libc.so.6 libgmp.so.3 libc.so.6(GLIBC_2.0) libc.so.6(GLIBC_2.1.3)

%description
Cyfer is a portable cryptographic library providing several implementations
of message digest, block and stream cipher and public-key algorithms. The
library is extremely modular, providing easy way to add or modify algorithm
implementations, or even separating the particular algorithm from the
library physically (suitable for embedded environments). Cyfer doesn't
support PKI (Public-Key Infrastructure).

%prep
%setup

%build
./configure --prefix=/usr
make

%install
make install DESTDIR=$RPM_BUILD_ROOT

%files
/lib/libcyfer-0.6.0.so
/lib/libcyfer.so
/lib/libcyfer.la
/lib/libcyfer.a
/usr/include/cyfer
%doc /usr/doc/cyfer-0.6.0

