# -*- coding: utf-8 -*-

# Copyright (c) nexb Inc., Google Inc., The github-release-retry Project Authors, and others
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pathlib import Path

from setuptools import setup
from setuptools import find_packages


def get_long_description() -> str:
    readme_path = Path(__file__).parent / "README.rst"
    return readme_path.read_text(encoding="utf-8")


setup(
    name="relrel",
    version="2021.1",
    description="A tool for creating GitHub Releases and uploading assets reliably.",
    long_description=get_long_description(),
    keywords="GitHub Release Releases reliable retry upload assets",
    author="nexB Inc. and others",
    url="https://github.com/nexB/relrel",
    license="Apache License 2.0",
    packages=find_packages('src'),
    package_dir={'': 'src'},
    python_requires=">=3.6",
    install_requires=[
        "attrs",
        "requests",
    ],
    classifiers=[
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3 :: Only",
    ],
    entry_points={
        "console_scripts": [
            "relrel = relrel:main",
        ]
    },
)
