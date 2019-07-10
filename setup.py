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

from setuptools import setup, find_packages
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pytor',
    version='1.0.0',
    description='Pure python tor protocol implementation',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/pytorx/pytor',
    author='James Brown',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='python proxy anonymity privacy socks tor protocol onion hiddenservice',
    packages=find_packages(exclude=['tests']),
    python_requires='>=3.0',
    install_requires=['cryptography', 'requests>=2.8.0,<2.12.0'],
    entry_points={'console_scripts': [
            'pytor_cli=pytor.cli.console:main',
            'pytor_socks=pytor.cli.socks:main',
        ],
    },
    project_urls={
        'Bug Reports': 'https://github.com/pytorx/pytor/issues',
        'Source': 'https://github.com/pytorx/pytor/',
    },
)