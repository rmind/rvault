PROJ=	rvault

all:
	@ echo "targets"
	@ echo "	make rpm"
	@ echo "	make deb"

prepare:
	@ awk '/APP_PROJ_VER/ { print $$3 }' \
	    ../src/core/rvault.h | tr -d '"' > version.txt
	mkdir -p SOURCES

rpm: prepare
	tar czpvf SOURCES/$(PROJ).tar.gz ../src
	rpmbuild -ba -v --define "_topdir ${PWD}" SPECS/$(PROJ).spec
	@ echo && printf "\x1B[32mRPM packages:\033[0m\n" && ls -1 RPMS/*

deb: prepare
	cp -R ../src ./SOURCES/$(PROJ)-$(shell cat version.txt)
	cd SOURCES && tar czpvf $(PROJ).tar.gz $(PROJ)-$(shell cat version.txt)
	dpkg-buildpackage -rfakeroot -us -uc -b
	@ echo && printf "\x1B[32mDEB packages:\033[0m\n" && ls -1 ../*.deb

clean:
	rm -rf BUILD BUILDROOT RPMS SOURCES SRPMS version.txt

.PHONY: all rpm deb clean
