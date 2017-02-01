# -*- coding: utf-8 -*-
"""
This module contains the Zope2 product AutoUserMakerPASPlugin: A Plone customization
"""
import os
from setuptools import setup, find_packages
def read(*rnames):
    return open(os.path.join(os.path.dirname(__file__), *rnames)).read()

version = '2.1'

long_description = (
    read('README.rst')
    + '\n' +
    'Change history\n'
    '**************\n'
    + '\n' +
    read('CHANGES.txt')
    + '\n' +
    'Detailed Documentation\n'
    '**********************\n'
    + '\n' +
    read('Products', 'AutoUserMakerPASPlugin', 'README.rst')
    + '\n' +
    'Contributors\n'
    '************\n'
    + '\n' +
    read('CONTRIBUTORS.txt')
    + '\n'
    )

setup(name='Products.AutoUserMakerPASPlugin',
      version=version,
      description="Automatically create PAS users when authentication in Plone",
      long_description=long_description,
      classifiers=[
        'Framework :: Zope2',
        'Framework :: Plone',
        'Framework :: Plone :: 4.1',
        'Framework :: Plone :: 4.2',
        'Framework :: Plone :: 4.3',
        'Framework :: Plone :: 5.0',
        'Framework :: Plone :: 5.1',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        ],
      keywords='plone authentication shibboleth pas security',
      author='Tom Gross',
      author_email='itconsense@gmail.com',
      url='http://pypi.python.org/pypi/Products.AutoUserMakerPASPlugin/',
      license='GPL',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['Products'],
      include_package_data=True,
      zip_safe=False,
      setup_requires=['setuptools-git'],
      install_requires=[
          'setuptools',
          'Products.PlonePAS'
      ],
      extras_require={
          'test': [
              'plone.app.testing',
              'plone.api'
          ],
      },
      entry_points=""" """,
      )
