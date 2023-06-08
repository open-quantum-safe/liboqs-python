from setuptools import find_packages
from distutils.core import setup

setup(
    packages=find_packages(exclude=('tests', 'docs', 'examples')),
)
