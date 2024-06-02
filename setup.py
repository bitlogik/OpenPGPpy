#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# OpenPGPpy : setup data
# Copyright (C) 2020-2024  BitLogiK

import os
from setuptools import setup, find_packages

with open("README.md") as readme_file:
    readme = readme_file.read()

setup(
    name="OpenPGPpy",
    version="1.2",
    description="OpenPGP smartcard communication library",
    long_description=readme + "\n\n",
    long_description_content_type="text/markdown",
    keywords="cryptography security openpgp hardware",
    author="BitLogiK",
    author_email="contact@bitlogik.fr",
    url="https://github.com/bitlogik/OpenPGPpy",
    license="GPLv3",
    python_requires=">=3.6",
    install_requires=["pyscard==2.0.8" if os.name == "nt" else "pyscard>=2.0.0"],
    extras_require={"dev": ["PyNaCl==1.5.0"]},  # For the demos
    package_data={},
    include_package_data=False,
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "Topic :: Communications :: Email",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Hardware",
    ],
    packages=find_packages(),
    zip_safe=False,
)
