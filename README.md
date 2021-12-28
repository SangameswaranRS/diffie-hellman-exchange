### Diffie Hellman Exchange

[![build](https://github.com/SangameswaranRS/diffie-hellman-exchange/actions/workflows/go.yml/badge.svg)](https://github.com/SangameswaranRS/diffie-hellman-exchange/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/SangameswaranRS/diffie-hellman-exchange)](https://goreportcard.com/report/github.com/SangameswaranRS/diffie-hellman-exchange)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


A simple but ***fastidious*** attempt to write a ***diffie-hellman*** key exchange
utility that could be used as ***transport upgraders*** in distributed systems.

If you are trying to use this in a traditional n tier computing environment, you are
crazy and use well tested default secure channels that are available with every library on the face
of earth.

All the keys are ***Serializable*** allowing you to transport them as you wish.
Transport is out of scope for this project.

##### Id reconciliation

This handshake creates a new Elliptic curve key(based on the curve you specify).
If you want to use this with some other systems with different identity mechanisms,

You may want to add a ***signature*** whenever you are transferring this public key. Use your
default curve to add a sign to the public key you would be transferring.

##### Wire support

Usually only Public keys are transferred, so the library provides marshal and unmarshal support for them.

##### Symmetric Encryption - AES GCM

After a common secret key is agreed upon, the lib also provides some
AES utils for encrypting and decrypting any random content you want.

### Usage

Refer the [tests](./ecdh_test.go) for usage. You may also want to refer the [interface](./diffie_hellman.go) for
clarity on the methods supported.