clean mrproper:
	-rm -f *.${EXT_SO} *.${EXT_AR} *.o
	-rm -rf *.dSYM

install:
	mkdir -p $(DESTDIR)/$(RZ_PLUGIN_PATH)
	[ -n "`ls *.$(EXT_SO)`" ] && cp -f *.$(EXT_SO) $(DESTDIR)/$(RZ_PLUGIN_PATH) || true

install-home:
	mkdir -p ${RZPM_PLUGDIR}
	[ -n "`ls *.$(EXT_SO)`" ] && \
		cp -f *.$(EXT_SO) ${RZPM_PLUGDIR} || true

uninstall:
	rm -f $(DESTDIR)/$(RZ_PLUGIN_PATH)/"`ls *.$(EXT_SO)`"

uninstall-home:
	rm -f $(RZPM_PLUGDIR)/"`ls *.$(EXT_SO)`"
