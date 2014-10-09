certificate handling for haskell
================================

This repository contains various certificates related PKIX X509 packages.

force reinstalling all x509 for dev:

    for i in x509 x509-store x509-system x509-validation; do (cd $i; cabal install --force-reinstall); done
