APXS=apxs2
APACHECTL=apache2ctl
APXS_OPTS=-Wc,-Wstrict-prototypes -Wc,-Werror -Wc,-Wall

#   here's what you may need to change

#   the default target
all: mod_ntraffic.so

#   compile the DSO file
mod_ntraffic.so: mod_ntraffic.c shm_pool.c
	$(APXS) $(APXS_OPTS) -n 'ntraffic' -c $(DEF) $(INC) $(LIB) mod_ntraffic.c shm_pool.c

#   install the DSO file into the Apache installation
#   and activate it in the Apache configuration
install: all
	$(APXS) -n 'ntraffic' -i -a .libs/mod_ntraffic.so

#   cleanup
clean:
	-rm -rf *.o *.so *.bak *.loT *.lo *.slo .libs *.la

#   reload the module by installing and restarting Apache
reload: install restart

#   the general Apache start/restart/stop procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

# my quick debug stuff
test: install stop start
	apache2ctl status
