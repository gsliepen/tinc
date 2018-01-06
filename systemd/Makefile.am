EXTRA_DIST = tinc.service.in tinc@.service.in

CLEANFILES = tinc.service tinc@.service

if WITH_SYSTEMD
systemddir = @systemd_path@
nodist_systemd_DATA = tinc.service tinc@.service
endif

substitute = sed \
        -e s,'@sbindir\@',"$(sbindir)",g \
        -e s,'@sysconfdir\@',"$(sysconfdir)",g

tinc.service: $(srcdir)/tinc.service.in
	$(AM_V_GEN)$(substitute) $(srcdir)/tinc.service.in > $@

tinc@.service: $(srcdir)/tinc@.service.in
	$(AM_V_GEN)$(substitute) $(srcdir)/tinc@.service.in > $@
