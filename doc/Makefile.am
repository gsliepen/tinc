## Process this file with automake to get Makefile.in

info_TEXINFOS = tinc.texi

man_MANS = tincd.8 tinc.conf.5

EXTRA_DIST = tincinclude.texi.in tincd.8.in tinc.conf.5.in sample-config.tar.gz

CLEANFILES = *.html tinc.info tincd.8 tinc.conf.5 tincinclude.texi

# Use `ginstall' in the definition of man_MANS to avoid
# confusion with the `install' target.  The install rule transforms `ginstall'
# to install before applying any user-specified name transformations.
transform = s/ginstall/install/; @program_transform_name@

# For additional rules usually of interest only to the maintainer,
# see GNUmakefile and Makefile.maint.

sample-config.tar.gz: sample-config
	GZIP=$(GZIP_ENV) $(AMTAR) chozf sample-config.tar.gz --exclude .svn sample-config

texi2html: tinc.texi
	texi2html -split=chapter tinc.texi

tincd.8.html: tincd.8
	w3mman2html $< > $@

tinc.conf.5.html: tinc.conf.5
	w3mman2html $< > $@

substitute = sed \
	-e s,'@PACKAGE\@',"$(PACKAGE)",g \
	-e s,'@VERSION\@',"$(VERSION)",g \
	-e s,'@sysconfdir\@',"$(sysconfdir)",g \
	-e s,'@localstatedir\@',"$(localstatedir)",g

tincd.8: tincd.8.in
	$(substitute) tincd.8.in > tincd.8

tinc.conf.5: tinc.conf.5.in
	$(substitute) tinc.conf.5.in > tinc.conf.5

tincinclude.texi: tincinclude.texi.in
	$(substitute) tincinclude.texi.in > tincinclude.texi
	
tinc.texi: tincinclude.texi
