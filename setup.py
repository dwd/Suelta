#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup
import sys

import suelta

VERSION          = suelta.__version__
DESCRIPTION      = 'Suelta - A pure-Python SASL client library'
LONG_DESCRIPTION = """
Suelta is a SASL library, providing you with authentication and in some
cases security layers.

It supports a wide range of typical SASL mechanisms, including the MTI for
all known protocols.
"""
CLASSIFIERS      = ['Intended Audience :: Developers',
                    'License :: OSI Approved :: MIT',
                    'Programming Language :: Python',
                    'Topic :: Software Development :: Libraries :: Python Modules']
PACKAGES         = ['suelta', 'suelta/mechanisms']

setup(
    name             = "suelta",
    version          = VERSION,
    description      = DESCRIPTION,
    long_description = LONG_DESCRIPTION,
    author       = 'Dave Cridland',
    author_email = 'dwd',
    url          = 'http://github.com/dwd/suelta',
    license      = 'MIT',
    platforms    = ['any'],
    packages     = PACKAGES
)
