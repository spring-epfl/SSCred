#!/usr/bin/env python
import os
import re

from setuptools import setup


PACKAGE_NAME = "sscred"
INSTALL_REQUIRES = ["petlib", "zksk"]
SETUP_REQUIRES = ["pytest-runner"]
TEST_REQUIRES = ["pytest"]


here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md")) as f:
    long_description = f.read()


with open(os.path.join(here, PACKAGE_NAME, "__init__.py")) as f:
    matches = re.findall(r"(__.+__) = \"(.*)\"", f.read())
    for var_name, var_value in matches:
        globals()[var_name] = var_value


setup(
    name=__title__,
    version=__version__,
    description=__description__,
    long_description=long_description,
    author=__author__,
    author_email=__email__,
    packages=[PACKAGE_NAME],
    # license=__license__,
    # url=__url__,
    install_requires=INSTALL_REQUIRES,
    setup_requires=SETUP_REQUIRES,
    tests_require=TEST_REQUIRES,
    extras_require={"test": TEST_REQUIRES},
    classifiers=[
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security :: Cryptography",
        "Topic :: Security :: Privacy",
        "Topic :: Security :: Signature",
        "Topic :: Security :: Authentication",
        # "License :: OSI Approved :: MIT License",
    ],
)