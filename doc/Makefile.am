## Process this file with automake to get Makefile.in

info_TEXINFOS = tinc.texi

man_MANS = tincd.8 tinc.conf.5

EXTRA_DIST = tincinclude.texi.in tincd.8.in tinc.conf.5.in sample-config.tar.gz

CLEANFILES = *.html

# Use `ginstall' in the definition of man_MANS to avoid
# confusion with the `install' target.  The install rule transforms `ginstall'
# to install before applying any user-specified name transformations.
transform = s/ginstall/install/; @program_transform_name@

# For additional rules usually of interest only to the maintainer,
# see GNUmakefile and Makefile.maint.

sample-config.tar.gz: sample-config
	GZIP=$(GZIP_ENV) $(AMTAR) --exclude .svn chozf sample-config.tar.gz sample-config

texi2html: tinc.texi
	texi2html -split=chapter tinc.texi

%.html: $(man_MANS)
	w3mman2html $< > $@
