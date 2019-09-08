=====
About
=====

How does it work?
=================

*AgentCrypt* encrypts or decrypts data with the help of `ssh private keys` from an `ssh-agent`.

- A public random value (`nonce`) is signed with the SSH key (``SSH_AGENTC_SIGN_REQUEST``) and then passed along
  with another random value (`salt`) to a key derivation function. This yields a `secret key`.
- The input data is encrypted with a symmetric cipher using the `secret key` from the previous step.
- The cipher-text is stored together with the `nonce` and the `salt`.

The fact that it is not possible to predict the nonce-signature without access to the private key or the agent
containing it, ensures that only the owner of the private SSH key can decrypt the data.

Limitations
===========

- *AgentCrypt* only works with RSA and ED25519 keys (see `key limitations`_).
- *AgentCrypt* cannot encrypt with multiple keys, making it impossible to share an encrypted container
  or encrypt with an additional backup key. It shouldn't be hard to implement that, but so far there was no use for it.
- Like all applications that rely on key-agents, *AgentCrypt* is susceptible to agent hijacking.
  You can make yourself (more or less) immune to that with the key-agent's confirmation option ``ssh-add -c <key>``.
  But that comes with the burden of having to type "*yes*" on the local machine, whenever *AgentCrypt* needs your key.

.. _key limitations:

Key limitations
  Not all signatures are deterministic, i.e. do not result in the same output for the same input. This is, repeated runs
  of the signature algorithm do not produce the same signature for the same input. The resulting values can of course be
  validated with public-key, but *AgentCrypt* cannot use it as a symmetric key.

  Asymmetric encryption and signing needs a random component to be secure. In case of RSA this is called padding (not to
  be confused with block cipher padding). SSH uses PKCS#1 v1.5 padding for RSA signatures, which is deterministic.
  That's why RSA keys work for us (RSA-PSS wouldn't). ED25519 signatures are deterministic too.

  For signatures with DSA and ECDSA keys there is a deterministic usage described in RFC-6979, but SSH doesn't implement
  it, thus these keys don't work for us.

  `DSA keys have been deprecated`_, so they should be replaced anyway. Whether to replace existing ECDSA keys depends on
  your trust in the `NSA and your random number generator`_. They cannot be used with *AgentCrypt* in any case.

..  _`DSA keys have been deprecated`: https://www.gentoo.org/support/news-items/2015-08-13-openssh-weak-keys.html
..  _`NSA and your random number generator`: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Concerns


Security
========

Probably the crunch question: *Is the signature a suitable means of deriving a symmetric key?*
  The signature can be used as secret, because it cannot be derived without the private key. Deriving the signature
  without the private key would be a successful “*signature forgery attack*”. If such an attack was known and efficient,
  it would probably have made it into the news.

  On the other hand, using the signature as symmetric key, is not a mode of operation you will find in the PKCS#xx
  documents. And the fact that the one value that qualifies as signature cannot be deduced, doesn't necessarily mean it
  is impossible to make assumptions about keys made from signatures. In order to make key enumeration expensive, even if
  such assumptions could be made, the signature is fed to PBKDF2  before using it as key.

Bottom line:
  This kind of encryption can be a convenient shortcut, if the alternative is plaintext storage. It shouldn't break on
  the first strike, but as with any home-brewed security implementation, you shouldn't use it, if the stakes are high.
