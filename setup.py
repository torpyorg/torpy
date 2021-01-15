# Copyright 2019 James Brown
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from io import open
from os import path

from setuptools import setup, find_packages

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='torpy',
    version='1.1.5',
    description='Pure python tor protocol implementation',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/torpyorg/torpy',
    author='James Brown',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    keywords='python proxy anonymity privacy socks tor protocol onion hiddenservice',
    packages=find_packages(exclude=['tests']),
    python_requires='>=3.6',
    install_requires=['cryptography>=3.2'],
    extras_require={'requests': 'requests>2.9,!=2.17.0,!=2.18.0'},
    entry_points={'console_scripts': ['torpy_cli=torpy.cli.console:main',
                                      'torpy_socks=torpy.cli.socks:main']
                  },
    project_urls={
        'Bug Reports': 'https://github.com/torpyorg/torpy/issues',
        'Source': 'https://github.com/torpyorg/torpy/',
    },
)
