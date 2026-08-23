%define version	%(cat %{_topdir}/version.txt)

Name:		rvault
Version:	%{version}
Release:	1%{?dist}
Summary:	Secure and authenticated store for small documents
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

Requires:	openssl-libs
Requires:	libscrypt
Requires:	libcurl
Requires:	fuse-libs
Requires:	fuse

%description

rvault is a secure and authenticated store for and small documents.
It uses _envelope encryption_ with one-time password (OTP) authentication.
It is written in modern C and distributed under the 2-clause BSD license.

%prep
%setup -q -n src

%build
make clean && make %{?_smp_mflags}

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
