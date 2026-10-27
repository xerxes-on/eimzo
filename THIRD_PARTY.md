# Third-party runtime

This repository's MIT license covers its original PHP code, Java bridge, installer, tests and documentation. It does not relicense E-IMZO, its cryptographic providers, or their bundled dependencies.

The runtime installer downloads, at the operator's request:

- Source: the Linux/macOS archive linked from <https://e-imzo.soliq.uz/download/>.
- Archive: <https://dls.soliq.uz/v6.4.7/E-IMZO-v6.4.7.tar.gz>.
- Version: 6.4.7.
- SHA-256: `c077152064cd44c8ade4ba877177061a2edfa039a2c0755751cc65e199611a76`.

The provider binaries are intentionally absent from Git, Composer release archives, and GitHub release assets. Operators obtain them from the official source and use them under the vendor's applicable terms. No right to redistribute those binaries is granted by this project. The vendor archive inspected for this integration did not include a general redistribution license for the YT provider; none is assumed.

The bridge uses the vendor's `PKCS12Reader`, `DocumentSigner`, `YTProvider` and signature verifier, plus bundled Bouncy Castle and Jackson APIs. These are version-specific dependencies. The bridge is independently written code, not a modified or decompiled vendor binary. The desktop application itself is not launched by native signing.

The installer builds the bridge locally against the downloaded files. Security updates require reviewing the new official archive, updating the checksum and running interoperability tests. Composer dependencies are separately tracked in `composer.lock` for development.
