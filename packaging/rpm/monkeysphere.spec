Name: monkeysphere
Summary: Use the OpenPGP web of trust to verify ssh connections
Version: 0.29
Release: 3
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
mkdir -p %{buildroot}%{_var}/lib/monkeysphere

%clean
%{__rm} -rf %{buildroot}

%pre
groupadd -r %{name} &>/dev/null || :
useradd -r -g %{name} -d %{_var}/lib/%{name} -s /bin/bash \
	-c "Monkeysphere authentication user" %{name} &>/dev/null || :
exit 0

%postun
test "$1" != 0 || userdel  %{name} &>/dev/null || :
test "$1" != 0 || groupdel %{name} &>/dev/null || :

%files
%defattr(-, root, root, 0755)

%dir %{_sysconfdir}/monkeysphere
%config(noreplace) %{_sysconfdir}/monkeysphere/monkeysphere-authentication.conf
%config(noreplace) %{_sysconfdir}/monkeysphere/monkeysphere-host.conf
%config(noreplace) %{_sysconfdir}/monkeysphere/monkeysphere.conf
%{_bindir}/monkeysphere
%{_bindir}/openpgp2ssh
%{_bindir}/pem2openpgp
%{_sbindir}/monkeysphere-authentication
%{_sbindir}/monkeysphere-host
%doc %dir %{_docdir}/monkeysphere
%doc %{_docdir}/monkeysphere/Changelog
%doc %{_docdir}/monkeysphere/MonkeySpec
%doc %{_docdir}/monkeysphere/TODO
%doc %{_docdir}/monkeysphere/getting-started-admin.mdwn
%doc %{_docdir}/monkeysphere/getting-started-user.mdwn
%doc %{_mandir}/man1/*
%doc %{_mandir}/man7/*
%doc %{_mandir}/man8/*
%doc %{_datadir}/monkeysphere/*
%dir %{_var}/lib/monkeysphere


%changelog
* Tue Mar 30 2010 Bernie Innocenti <bernie@codewiz.org> - 0.28-3
- Give a real shell to monkeysphere user.
- Simplify pre/postun macros.

* Tue Mar 30 2010 Bernie Innocenti <bernie@codewiz.org> - 0.28-2
- Create user monkeysphere on installation.

* Tue Mar 30 2010 Bernie Innocenti <bernie@codewiz.org> - 0.28-1
- Update to 0.28.
- Various fixes for Fedora.

* Sat Nov 22 2008 Anonymous Coward <anonymous@example.com> - 0.22
- Initial release.
