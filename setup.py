# -*- coding: utf-8 -*-

# Learn more: https://github.com/kennethreitz/setup.py

from setuptools import setup, find_packages


with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='SSVC Ore Miner',
    version='0.1.0',
    description='Sample package for Python-Guide.org',
    long_description=readme,
    author='Rapticore, Inc',
    author_email='support@rapticore.com',
    url='',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)

