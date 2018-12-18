This is a collection of command-line tools and utility classes which are useful
for interacting with the [pwnedkeys.com](https://pwnedkeys.com) compromised key
database.  You can search the database to determine whether a key you have is
compromised, or create a signed attestation of compromise for a key you have.

These tools are all written in Ruby, and require a fairly modern Ruby installation
(version 2.5 or later).  If you have such a setup, you can [install the tools
as a gem](#installation).  Otherwise, if you have Docker, you can [use the
wrapper scripts to run the tools via a docker container](#docker-wrapper-scripts).


# Installation

Due to recent changes in the `openssl` standard library, the tools require
Ruby 2.5 or later with the `openssl` extension.  Assuming you've got that
available, you can install the tools as a gem:

    gem install pwnedkeys-tools

If you're the sturdy type that likes to run from git:

    rake install

Or, if you've eschewed the convenience of Rubygems entirely, then you
presumably know what to do already.


## Docker Wrapper Scripts

For those of you who don't have a bleeding edge Ruby installation laying
around, but *do* have a Docker installation, you can copy the scripts in
the `docker-wrappers` subdirectory into a directory in your `PATH`, and
you'll be ready to go.


# Usage

Whether you're running as a gem or via Docker, the command line tools have the
same names and usage.

## Query for a pwned key

Run `pwnedkeys-query`, passing a public or private key, CSR, X.509 certificate,
or SSH public key via `stdin`:

    pwnedkeys-query < /etc/ssl/certs/ssl-cert-snakeoil.pem

The exit status indicates whether the key is in the pwnedkeys database or not:

* **`0`** -- the key is **not** known to be compromised.

* **`1`** -- the key is known to be compromised, and should not be used.

* **`2`** -- some sort of error occurred, and the key's status is undetermined.
  An error message should have been printed on `stderr`.


## Generate a compromise attestation

If you have a key you'd like to submit to the pwnedkeys database, the best way
to do it is to e-mail the key itself to `submit@pwnedkeys.com`.  However, if
for some reason you really, *really* don't want to do that, you can generate
your own compromise attestation and e-mail *that* (along with the public key,
so *we* can verify the attestation is legit) to `submit@pwnedkeys.com`.

To generate an attestation, run `pwnedkeys-prove-pwned`, passing in a
private key on `stdin`:

    pwnedkeys-prove-pwned < /etc/ssl/private/ssl-cert-snakeoil.key

A JSON blob, containing the attestation and signature, will be output on
`stdout`.


# Contributing

Bug reports should be sent to the [GitHub issue
tracker](https://github.com/pwnedkeys/pwnedkeys-tools/issues).  Patches can be
sent as a [GitHub pull
request](https://github.com/pwnedkeys/pwnedkeys-tools/pulls).


# Licence

Unless otherwise stated, everything in this repo is covered by the following
copyright notice:

    Copyright (C) 2018  Matt Palmer <matt@hezmatt.org>

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License version 3, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

	In addition, as a special exception, the copyright holders give permission
	to link the code of portions of this program with the OpenSSL library. You
	must obey the GNU General Public License in all respects for all of the
	code used other than OpenSSL. If you modify file(s) with this exception,
	you may extend this exception to your version of the file(s), but you are
	not obligated to do so. If you do not wish to do so, delete this exception
	statement from your version. If you delete this exception statement from
	all source files in the program, then also delete it here.
