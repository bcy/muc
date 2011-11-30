EXTRA_DIST = muc.xml.dist.in

SUBDIRS = src scripts
sysconf_DATA = muc.xml.dist


edit = sed \
       -e 's,\@sysconfdir\@,$(sysconfdir),g' \
       -e 's,\@localstatedir\@,$(localstatedir),g'

$(sysconf_DATA):
	@echo "generating $@ from $@.in"; \
	edit='$(edit)'; \
	rm -f $@ $@.tmp; \
	eval "$$edit < $@.in > $@.tmp"; \
	mv $@.tmp $@

install-data-hook:
	@list='$(sysconf_DATA)'; for p in $$list; do \
		dest=`echo $$p | sed -e s/.dist//`; \
		if test -f $(DESTDIR)$(sysconfdir)/$$dest; then \
			echo "$@ will not overwrite existing $(DESTDIR)$(sysconfdir)/$$dest"; \
		else \
			echo " $(INSTALL_DATA) $$p $(DESTDIR)$(sysconfdir)/$$dest"; \
			$(INSTALL_DATA) $$p $(DESTDIR)$(sysconfdir)/$$dest; \
		fi; \
	done

clean-local:
	rm -f $(sysconf_DATA)
