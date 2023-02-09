# -*- coding: utf-8 -*-

# Learn more: https://github.com/kennethreitz/setup.py

from setuptools import setup, find_packages

REQUIRED = []

with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

with open('requirements.txt') as f:
    while True:
        line = f.readline()
        if not line:
            break
        REQUIRED.append(line.strip())

setup(
    name='rapticoressvc',
    description='Rapticore SSVC ORE Miner',
    classifiers=[
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    long_description_content_type="text/markdown",
    long_description=readme,
    author='Rapticore, Inc',
    author_email='support@rapticore.com',
    url='',
    license=license,
    install_requires=REQUIRED,
    packages=find_packages(exclude=('tests', 'docs')),
    include_package_data=True,
    package_data={
            "rapticoressvc": ["ssvc_impact_options.csv", "priority-options_v2.csv", "ssvc_utility_options.csv", "data_vulnerability.csv"],
        },
)

