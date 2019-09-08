#!/usr/bin/env python
# -*- coding: utf-8 -*-

import distutils
from distutils.command.clean import clean as _clean
import glob
import os
from setuptools import setup, find_packages
import shutil
import agentcrypt


class Clean(_clean, object):
    """Customized implementation of ``clean`` to get rid of the traces from `stdeb`."""
    def run(self):
        super(Clean, self).run()
        for pkg in self.distribution.packages:
            rm_dirs = ["{}.egg-info".format(pkg), "dist", "deb_dist"]
            for rm_dir in rm_dirs:
                if os.path.isdir(rm_dir):
                    distutils.log.info("removing directory {}".format(rm_dir))
                    shutil.rmtree(rm_dir)

            for rm_file in glob.glob("{}-?.*.*.tar.gz".format(pkg)):
                distutils.log.info("removing file {}".format(rm_file))
                os.unlink(rm_file)

#
# Packaging that worked:
#  Debian 9.8: python setup.py --command-packages=stdeb.command bdist_deb
#              python3 setup.py --command-packages=stdeb.command bdist_deb
#  Centos 7.6: python setup.py bdist_rpm
#
# Tests may fail before the library is on the path. To skip:
#  DEB_BUILD_OPTIONS=nocheck python[3] setup.py --command-packages=stdeb.command bdist_deb
#
setup(
    author="Dirk Heuvels",
    author_email='coding@heuvels.de',

    classifiers=[
        'Development Status :: 4 - Beta'
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    
    name=agentcrypt.__name__,
    keywords=agentcrypt.__name__,

    description="Symmetric encryption using the ssh-agent",
    long_description="""Yet another implementation of the idea, to use the SSH agent for symmetric encryption.
This time for Python (2+3).""",

    install_requires=['cryptography', 'paramiko', 'future'],
    license="GNU General Public License v3",

    version=agentcrypt.__version__,
    packages=find_packages(include=['agentcrypt', 'tests']),
    # ED25519 keys need paramiko >=2.2 (affects only the tests).
    tests_require = ['cryptography', 'paramiko>=2.2', 'future', 'pytest'],
    zip_safe=True,

    command_options={
        'build_sphinx': {
            'project': ('setup.py', agentcrypt.__name__),
            'version': ('setup.py', agentcrypt.__version__),
            'release': ('setup.py', agentcrypt.__version__),
            'source_dir': ('setup.py', 'sphinx'),
            'build_dir': ('setup.py', '_private'),
        }
    },

    cmdclass={
        'clean': Clean,
    },
)
