# -*- coding: utf-8 -*-


class AgentCryptException(Exception):
    """
    Any error condition within the library is indicated by raising `AgentCryptException`.

    Additional information about the root cause can be obtained by inspecting the ``__cause__`` attribute set by
    `raise from`_.  If anything else than `AgentCryptException` is raised by an agentcrypt module, either a library is
    missing or it is probably a bug.

    .. _`raise from`: https://docs.python.org/3/reference/simple_stmts.html#raise
    """
    def __init__(self, message):
        super(AgentCryptException, self).__init__(message)


class NoContainerException(AgentCryptException):
    """Sub class of `AgentCryptException` that is raised, when an existing container cannot be loaded.
    """
    def __init__(self, message):
        super(NoContainerException, self).__init__(message)
