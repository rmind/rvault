PROJ=		rvault
RPM_WITH?=	# "--with sqlite"

all:
	@ echo "targets"
	@ echo "	make rpm"
	@ echo "	make deb"
	@ echo "	make osx-pkg"

prepare:
	@ awk '/APP_PROJ_VER/ { print $$3 }' \
	    ../src/core/rvault.h | tr -d '"' > version.txt
	mkdir -p SOURCES

rpm: prepare
	tar czpvf SOURCES/$(PROJ).tar.gz ../src
	rpmbuild -ba -v --define "_topdir ${PWD}" ${RPM_WITH} SPECS/$(PROJ).spec
	@ echo && printf "\x1B[32mRPM packages:\033[0m\n" && ls -1 RPMS/*

deb: prepare
	cp -R ../src ./SOURCES/$(PROJ)-$(shell cat version.txt)
	cd SOURCES && tar czpvf $(PROJ).tar.gz $(PROJ)-$(shell cat version.txt)
	dpkg-buildpackage -rfakeroot -us -uc -b
	@ echo && printf "\x1B[32mDEB packages:\033[0m\n" && ls -1 ../*.deb

osx-pkg: prepare
	cp -R ../src/ ./SOURCES
	cd ./SOURCES && make -j8 && \
	    make install DESTDIR="$(PWD)/BUILDROOT" \
	    MANDIR="/usr/local/share/man" BINDIR="/usr/local/bin"
	pkgbuild --root BUILDROOT \
	    --identifier eu.noxt.$(PROJ).pkg \
	    --version $(shell cat version.txt) \
	    --ownership recommended \
	    $(PROJ)-$(shell cat version.txt).pkg
	@ echo && printf "\x1B[32mDEB packages:\033[0m\n" && ls -1 *.pkg

clean:
	rm -rf BUILD BUILDROOT RPMS SOURCES SRPMS version.txt *.pkg

.PHONY: all rpm deb osx-pkg clean
