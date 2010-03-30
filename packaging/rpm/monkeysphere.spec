Name: monkeysphere
Summary: Use the OpenPGP web of trust to verify ssh connections
Version: 0.29
Release: 1
License: GPLv3+
Group: Applications/Internet
URL: http://web.monkeysphere.info/

Source: http://archive.monkeysphere.info/debian/pool/monkeysphere/m/monkeysphere/monkeysphere_%{version}.orig.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires: gnupg
Requires: openssh-clients


%description
SSH key-based authentication is tried-and-true, but it lacks a true
Public Key Infrastructure for key certification, revocation and
expiration.  Monkeysphere is a framework that uses the OpenPGP web of
trust for these PKI functions.  It can be used in both directions: for
users to get validated host keys, and for hosts to authenticate users.

%prep
%setup -q

%build
%{__make} %{?_smp_mflags}

%install
%{__rm} -rf %{buildroot}
make DESTDIR=%{buildroot} install

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)

%config(noreplace) %{_sysconfdir}/monkeysphere/monkeysphere-authentication.conf
%config(noreplace) %{_sysconfdir}/monkeysphere/monkeysphere-host.conf
%config(noreplace) %{_sysconfdir}/monkeysphere/monkeysphere.conf
%{_bindir}/monkeysphere
%{_bindir}/openpgp2ssh
%{_bindir}/pem2openpgp
%{_sbindir}/monkeysphere-authentication
%{_sbindir}/monkeysphere-host
%doc %{_docdir}/monkeysphere/Changelog
%doc %{_docdir}/monkeysphere/MonkeySpec
%doc %{_docdir}/monkeysphere/TODO
%doc %{_docdir}/monkeysphere/getting-started-admin.mdwn
%doc %{_docdir}/monkeysphere/getting-started-user.mdwn
%{_mandir}/man1/*
%{_mandir}/man7/*
%{_mandir}/man8/*
%{_datadir}/monkeysphere/*


%changelog
* Tue Mar 30 2010 Bernie Innocenti <bernie@codewiz.org> - 0.28
- Update to 0.28.
- Various fixes for Fedora.

* Sat Nov 22 2008 Anonymous Coward <anonymous@example.com> - 0.22
- Initial release.
