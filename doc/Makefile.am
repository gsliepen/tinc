## Process this file with automake to get Makefile.in

info_TEXINFOS = tinc.texi
tinc_TEXINFOS = tincinclude.texi

man_MANS = tincd.8 tinc.8 tinc.conf.5 tinc-gui.8

EXTRA_DIST = tincinclude.texi.in tincd.8.in tinc.8.in tinc.conf.5.in tinc-gui.8.in sample-config

CLEANFILES = *.html tincd.8 tinc.8 tinc.conf.5 tinc-gui.8 tincinclude.texi

tincd.8.html: tincd.8
	$(AM_V_GEN)w3mman2html $? > $@

tinc.8.html: tinc.8
	$(AM_V_GEN)w3mman2html $? > $@

tinc-gui.8.html: tinc-gui.8
	$(AM_V_GEN)w3mman2html $? > $@

tinc.conf.5.html: tinc.conf.5
	$(AM_V_GEN)w3mman2html $? > $@

substitute = sed \
	-e s,'@PACKAGE\@',"$(PACKAGE)",g \
	-e s,'@VERSION\@',"$(VERSION)",g \
	-e s,'@sysconfdir\@',"$(sysconfdir)",g \
	-e s,'@runstatedir\@',"$(runstatedir)",g \
	-e s,'@localstatedir\@',"$(localstatedir)",g

tincd.8: $(srcdir)/tincd.8.in
	$(AM_V_GEN)$(substitute) $(srcdir)/tincd.8.in > $@

tinc.8: $(srcdir)/tinc.8.in
	$(AM_V_GEN)$(substitute) $(srcdir)/tinc.8.in > $@

tinc-gui.8: $(srcdir)/tinc-gui.8.in
	$(AM_V_GEN)$(substitute) $(srcdir)/tinc-gui.8.in > $@

tinc.conf.5: $(srcdir)/tinc.conf.5.in
	$(AM_V_GEN)$(substitute) $(srcdir)/tinc.conf.5.in > $@

tincinclude.texi: $(srcdir)/tincinclude.texi.in
	$(AM_V_GEN)$(substitute) $(srcdir)/tincinclude.texi.in > $@
