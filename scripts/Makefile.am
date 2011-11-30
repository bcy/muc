EXTRA_DIST = create_room.sh.in change_nameprefix.sh.in roommaker.pl.in roomname.pl.in room.dist.in
sysconf_DATA = room.dist
bin_SCRIPTS = create_room.sh change_nameprefix.sh roommaker.pl roomname.pl

CLEANFILES = $(bin_SCRIPTS) $(sysconf_DATA)

do_subst = sed -e 's,[@]localstatedir[@],$(localstatedir),g' \
	   -e 's,[@]sysconfdir[@],$(sysconfdir),g'

create_room.sh: create_room.sh.in Makefile
	$(do_subst) < $(srcdir)/create_room.sh.in > create_room.sh
	chmod +x create_room.sh

change_nameprefix.sh: change_nameprefix.sh.in Makefile
	$(do_subst) < $(srcdir)/change_nameprefix.sh.in > change_nameprefix.sh
	chmod +x change_nameprefix.sh

roommaker.pl: roommaker.pl.in Makefile
	$(do_subst) < $(srcdir)/roommaker.pl.in > roommaker.pl
	chmod +x roommaker.pl

roomname.pl: roomname.pl.in Makefile
	$(do_subst) < $(srcdir)/roomname.pl.in > roomname.pl
	chmod +x roomname.pl

$(sysconf_DATA):
	@echo "generating $@ from $@.in"; \
	edit='$(do_subst)'; \
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

