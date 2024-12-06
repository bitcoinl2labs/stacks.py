#!/usr/bin/env python3

from setuptools import setup, find_packages
import os

setup(
    name="stacks",
    version="0.1",
    description="The Swiss Army Knife of the Bitcoin protocol.",
    classifiers=[
        "Programming Language :: Python",
    ],
    url="https://github.com/bitcoinl2labs/stacks.py",
    keywords="bitcoin",
    packages=find_packages(),
    zip_safe=False,
    install_requires=["ecdsa"],
    test_suite="stacks.tests",
)
