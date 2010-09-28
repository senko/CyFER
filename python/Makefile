.PHONY: all build dist clean test install
CFLAGS = -I../include
LDFLAGS = -L../lib/.libs

all: build

build:
	CFLAGS=$(CFLAGS) LDFLAGS=$(LDFLAGS) ./setup.py build
	test -L cyfer || ln -s build/lib.*/cyfer cyfer
	touch cyfer/__init__.py 

clean:
	./setup.py clean
	rm -rf build dist cyfer
	

dist: build
	./setup.py bdist

test: build
	LD_LIBRARY_PATH=../lib/.libs ./test.py


install: build
	./setup.py install

