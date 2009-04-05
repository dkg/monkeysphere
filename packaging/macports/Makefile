# use proper system paths for MacPorts instead of Debian's:
post-patch:
	@${REINPLACE_CMD} -e 's|/etc/monkeysphere|'$(SYSETCDIR)'|g' \
	  ${WRKSRC}/src/share/defaultenv \
	  ${WRKSRC}/src/transitions/0.23 \
	  ${WRKSRC}/man/man1/monkeysphere.1 \
	  ${WRKSRC}/man/man8/monkeysphere-authentication.8 \
	  ${WRKSRC}/man/man8/monkeysphere-host.8 \
	  ${WRKSRC}/etc/monkeysphere-authentication.conf
	@${REINPLACE_CMD} -e 's|/var/lib/monkeysphere|'$(SYSDATADIR)'|g' \
	  ${WRKSRC}/src/transitions/0.23 \
	  ${WRKSRC}/man/man1/monkeysphere.1 \
	  ${WRKSRC}/man/man8/monkeysphere-authentication.8 \
	  ${WRKSRC}/man/man8/monkeysphere-host.8 \
	  ${WRKSRC}/src/monkeysphere-host \
	  ${WRKSRC}/src/monkeysphere-authentication \
	  ${WRKSRC}/doc/getting-started-admin.mdwn
	@${REINPLACE_CMD} -e 's|/usr/share/monkeysphere|'$(SYSSHAREDIR)'|g' \
	  ${WRKSRC}/src/monkeysphere-host \
	  ${WRKSRC}/src/monkeysphere-authentication \
	  ${WRKSRC}/src/monkeysphere
	# and clean up cruft from the sed replacements:
	${FIND} ${WRKSRC} -name '*.bak' -delete
