# qlib

This is a library for performing DNS queries.  Its API is similar to [the command-line tool `q` by Miek Gieben](https://github.com/miekg/exdns/tree/master/q) (and in fact `qlib` is a fork of `q`), but its API is exposed as a Go library instead of a command-line tool.

# Original miekg/exdns README

[![Build Status](https://travis-ci.org/miekg/exdns.svg?branch=master)](https://travis-ci.org/miekg/exdns)
[![BSD 2-clause license](https://img.shields.io/github/license/miekg/exdns.svg?maxAge=2592000)](https://opensource.org/licenses/BSD-2-Clause)

# Examples made with Go DNS

This repository has a bunch of example programs that
are made with the https://github.com/miekg/dns Go package.

Currently they include:

* `as112`: an AS112 black hole server
* `chaos`: show DNS server identity
* `check-soa`: check the SOA record of zones for all nameservers
* `q`: dig-like query tool
* `reflect`: reflection nameserver
