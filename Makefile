LIBDIR=/usr/lib/wb-mqtt-orvibo

.PHONY: all clean

all:
clean :

install: all
	install -d $(DESTDIR)
	install -d $(DESTDIR)/etc
	install -d $(DESTDIR)/usr
	install -d $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/usr/lib
	install -d $(DESTDIR)/$(LIBDIR)

	install -m 0755 wb-mqtt-orvibo.py   $(DESTDIR)/$(LIBDIR)/

	ln -s  $(LIBDIR)/wb-mqtt-orvibo.py $(DESTDIR)/usr/bin/wb-mqtt-orvibo
