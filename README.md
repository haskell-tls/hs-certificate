certificate handling for haskell
================================

[![Build Status](https://travis-ci.org/vincenthz/hs-certificate.png?branch=master)](https://travis-ci.org/vincenthz/hs-certificate)
[![BSD](http://b.repl.ca/v1/license-BSD-blue.png)](http://en.wikipedia.org/wiki/BSD_licenses)
[![Haskell](http://b.repl.ca/v1/language-haskell-lightgrey.png)](http://haskell.org)

This repository contains various certificates related PKIX X509 packages.

force reinstalling all x509 for dev:

    for i in x509 x509-store x509-system x509-validation; do (cd $i; cabal install --force-reinstall); done
