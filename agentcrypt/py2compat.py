# -*- coding: utf-8 -*-

from __future__ import absolute_import

from io import IOBase
import sys


"""
Free floating, io related Python2 compatibility code.
"""


def is_file(file_candidate):
    if sys.version_info[0] == 2:
        return isinstance(file_candidate, file)
    else:
        return isinstance(file_candidate, IOBase)


def try_truncate(handle):
    try:
        # truncate() raises if not seekable, but seekable() cannot be checked, if it is a PY2 legacy file object.
        handle.truncate(0)
        handle.seek(0)
    except IOError:
        pass


def try_bytes(str):
    # Another opportunistic byte conversion to utf-8 but resistant to `None` values.
    try:
        return str.encode()
    except AttributeError:
        pass
    return str
