==========
Readme
==========

Abstract
========

Yet another implementation of the idea, to use the SSH agent for symmetric encryption.
This time for Python (2+3).

Load a key and make an SSH connection with agent-forwarding:

.. code-block:: bash

    local-machine ~ % ssh-add
    local-machine ~ % ssh -A remote-machine

Use or create some `agentcrypt` enabled scripts on the remote host:

.. code-block:: python

    remote-machine ~ % cat << '_EOF_' > encryptor.py
    import sys
    from agentcrypt.io import Container
    with Container.create(sys.stdout) as cntr:
      for line in sys.stdin:
        cntr.write(line)
    _EOF_

    % cat << '_EOF_' > decryptor.py
    import sys
    from agentcrypt.io import Container
    with Container.load(sys.stdin) as cntr:
        print(cntr.getvalue().decode())
    _EOF_

Use the private key from the forwarded ssh-agent for crypto operations:

.. code-block:: bash

    % echo "secret data" |python encryptor.py > hushhush.dat
    % python decryptor.py < hushhush.dat
    secret data

Or via the ``main`` guard:

.. code-block:: bash

    % echo "secret data" |python -magentcrypt.io enc > hushhush.dat
    % python -magentcrypt.io dec < hushhush.dat
    secret data


Motivation
==========

- Provide a convenient (passwordless) way of encrypting sensitive data for Python.
- Profit from the fact that agent-forwarding makes SSH keys available on remote servers.

Alternatives
============

- https://github.com/edwardspeyer/sshovel - Python
- https://github.com/is/sshcrypt - Go
- https://github.com/jwhitham/safeu - C (not sure if it uses the signature as keys too)

Why another implementation?
  The ones I found on GitHub are either not Python or they rely on calls to external programs.
  I wanted a pure Python library, that runs with Versions 2.7 and 3.x.

`Documentation`_
================

.. _Documentation: sphinx/build/html/index.html
