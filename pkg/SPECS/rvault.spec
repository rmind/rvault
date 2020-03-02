%define version	%(cat %{_topdir}/version.txt)
%bcond_with sqlite

Name:		rvault
Version:	%{version}
Release:	1%{?dist}
Summary:	Secure and authenticated store for secrets and small documents
Group:		Applications/File
License:	BSD
URL:		https://github.com/rmind/rvault
Source0:	rvault.tar.gz

BuildRequires:	make
# For test stage:
BuildRequires:	libasan
BuildRequires:	libubsan

BuildRequires:	openssl-devel
BuildRequires:	libscrypt-devel
BuildRequires:	fuse-devel
BuildRequires:	libcurl-devel
%if %{with sqlite}
BuildRequires:	readline-devel
BuildRequires:	sqlite-devel
%endif

Requires:	openssl-libs
Requires:	libscrypt
Requires:	libcurl
Requires:	fuse-libs
Requires:	fuse
%if %{with sqlite}
Requires:	readline
Requires:	sqlite-libs
%endif

%description

rvault is a secure and authenticated store for secrets (passwords,
keys, certificates) and small documents.  It uses _envelope encryption_
with one-time password (OTP) authentication.  It is written in C11 and
distributed under the 2-clause BSD license.

%prep
%setup -q -n src

%check
make clean && make tests

%build
make clean && make %{?_smp_mflags} %{?with_sqlite:USE_SQLITE=1}

%install
make install \
    DESTDIR=%{buildroot} \
    BINDIR=%{_bindir} \
    LIBDIR=%{_libdir} \
    MANDIR=%{_mandir}

%files
%{_bindir}/*
%{_mandir}/*

%changelog
