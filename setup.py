#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# OpenPGPpy : setup data
# Copyright (C) 2020  BitLogiK

from setuptools import setup, find_packages


setup(
    name="OpenPGPpy",
    version="0.1",
    description="OpenPGP smartcard communication library",
    author="BitLogiK",
    author_email="contact@bitlogik.fr",
    url="https://github.com/bitlogik/OpenPGPpy",
    license="GPLv3",
    python_requires=">=3.6,<3.9",
    install_requires=["pyscard"],
    extras_require={"dev": ["PyNaCl==1.4.0"]},
    package_data={},
    include_package_data=False,
    packages=find_packages(),
    zip_safe=False,
)
