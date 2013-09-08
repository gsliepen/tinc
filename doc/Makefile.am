## Process this file with automake to get Makefile.in

info_TEXINFOS = tinc.texi

man_MANS = tincd.8 tinc.8 tinc.conf.5 tinc-gui.8

EXTRA_DIST = tincinclude.texi.in tincd.8.in tinc.8.in tinc.conf.5.in tinc-gui.8.in sample-config.tar.gz

CLEANFILES = *.html tincd.8 tinc.8 tinc.conf.5 tinc-gui.8 tincinclude.texi

# Use `ginstall' in the definition of man_MANS to avoid
# confusion with the `install' target.  The install rule transforms `ginstall'
# to install before applying any user-specified name transformations.
transform = s/ginstall/install/; @program_transform_name@

# For additional rules usually of interest only to the maintainer,
# see GNUmakefile and Makefile.maint.

sample-config.tar.gz: sample-config
	GZIP=$(GZIP_ENV) $(AMTAR) chozf sample-config.tar.gz --exclude .svn sample-config

tincd.8.html: tincd.8
	w3mman2html $? > $@

tinc.8.html: tinc.8
	w3mman2html $? > $@

tinc-gui.8.html: tinc-gui.8
	w3mman2html $? > $@

tinc.conf.5.html: tinc.conf.5
	w3mman2html $? > $@

substitute = sed \
	-e s,'@PACKAGE\@',"$(PACKAGE)",g \
	-e s,'@VERSION\@',"$(VERSION)",g \
	-e s,'@sysconfdir\@',"$(sysconfdir)",g \
	-e s,'@localstatedir\@',"$(localstatedir)",g

tincd.8: tincd.8.in
	$(substitute) $? > $@

tinc.8: tinc.8.in
	$(substitute) $? > $@

tinc-gui.8: tinc-gui.8.in
	$(substitute) $? > $@

tinc.conf.5: tinc.conf.5.in
	$(substitute) $? > $@

tincinclude.texi: tincinclude.texi.in
	$(substitute) $? > $@
	
tinc.texi: tincinclude.texi
