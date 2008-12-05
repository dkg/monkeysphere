Name: monkeysphere
Summary: use the OpenPGP web of trust to verify ssh connections
Version: 0.22~pre
Release: 1
License: GPLv3
Group: net
URL: http://web.monkeysphere.info/

Source: http://archive.monkeysphere.info/debian/pool/monkeysphere/m/monkeysphere/monkeysphere_%{version}.orig.tar.gz

%description
SSH key-based authentication is tried-and-true, but it lacks a true
Public Key Infrastructure for key certification, revocation and
expiration.  Monkeysphere is a framework that uses the OpenPGP web of
trust for these PKI functions.  It can be used in both directions: for
users to get validated host keys, and for hosts to authenticate users.

Monkeysphere is free software released under the GNU General Public
License (GPL).

%prep
%setup -q

%build
%{__make}

%install
%{__rm} -rf %{buildroot}
Prefix=%{buildroot}/usr
%makeinstall

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)

%changelog
* Sat Nov 22 2008 - 
- Initial release.
