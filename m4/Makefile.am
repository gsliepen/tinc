## Process this file with automake to produce Makefile.in   -*-Makefile-*-

##m4-files-begin
EXTRA_DIST = README Makefile.am.in malloc.m4 perl.m4 realloc.m4

##m4-files-end

Makefile.am: Makefile.am.in
	rm -f $@ $@t
	sed -n '1,/^##m4-files-begin/p' $< > $@t
	( echo EXTRA_DIST = README Makefile.am.in; \
	  find . -type f -name '*.m4' -print |sed 's,^\./,,' |sort ) \
	  |fmt | (tr '\012' @; echo) \
	      |sed 's/@$$/%/;s/@/ \\@/g' |tr @% '\012\012' \
	        >> $@t
	sed -n '/^##m4-files-end/,$$p' $< >> $@t
	chmod a-w $@t
	mv $@t $@
