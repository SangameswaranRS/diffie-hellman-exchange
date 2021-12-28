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