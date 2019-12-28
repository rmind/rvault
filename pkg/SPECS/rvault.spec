%define version	%(cat %{_topdir}/version.txt)

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
BuildRequires:	readline-devel
BuildRequires:	sqlite-devel

Requires:	openssl-libs
Requires:	libscrypt
Requires:	fuse-libs
Requires:	libcurl
Requires:	readline
Requires:	sqlite-libs

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
make clean && make %{?_smp_mflags}
# make %{?_smp_mflags} lib LIBDIR=%{_libdir}

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
