#!/usr/bin/env python

from distutils.core import setup, Extension

# Change if appropriate
incdir = [];
libdir = [];
defines = [('MAJOR_VERSION', '0'), ('MINOR_VERSION', '6'), ('HAVE_ALLOCA_H', 1) ];

# If your system doesn't have 'alloca.h', 
hash = Extension('cyfer.hash',
					define_macros = defines,
                    include_dirs = incdir,
                    libraries = ['cyfer'],
                    library_dirs = libdir,
                    sources = ['src/hash.c'])

blockcipher = Extension('cyfer.blockcipher',
					define_macros = defines,
                    include_dirs = incdir,
                    libraries = ['cyfer'],
                    library_dirs = libdir,
                    sources = ['src/bcipher.c'])

streamcipher = Extension('cyfer.streamcipher',
					define_macros = defines,
                    include_dirs = incdir,
                    libraries = ['cyfer'],
                    library_dirs = libdir,
                    sources = ['src/scipher.c'])

pk = Extension('cyfer.pk',
					define_macros = defines,
                    include_dirs = incdir,
                    libraries = ['cyfer'],
                    library_dirs = libdir,
                    sources = ['src/pk.c'])

keyex = Extension('cyfer.keyex',
					define_macros = defines,
                    include_dirs = incdir,
                    libraries = ['cyfer'],
                    library_dirs = libdir,
                    sources = ['src/keyex.c'])

setup (name = 'Cyfer',
       version = '0.6.0',
       author = 'Senko Rasic',
       author_email = 'senko@senko.net',
       url = '',
	   description = 'Python wrapper for Cyfer cryptographic library.',
       ext_modules = [hash, blockcipher, streamcipher, pk, keyex])

