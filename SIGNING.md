# Verifying ArchiveGenocide release signatures

Zero Breach v0.1.8 supplies detached GPG signatures for the exact released
scanner and its SHA256SUMS.txt manifest. They use ArchiveGenocide's existing
Ed25519 release-signing key, also published on the archive's verification page.

Official repository: https://github.com/interplains/zero-breach
Official release: https://github.com/interplains/zero-breach/releases/tag/v0.1.8
Independent publisher page: https://archivegenocide.com/scan/#verify-download
Established key identity: https://archivegenocide.com/verify.html

## Check the publisher and file

Download these three files from the v0.1.8 release into one directory:

- zero-breach.py
- zero-breach.py.asc
- archivegenocide-signing-key.asc

The public key is also available at https://archivegenocide.com/key.asc.
Before trusting a supplied key, compare its complete fingerprint with the
official verification page or a previously trusted record:

    C24E C92B 12D6 670A 2516 065F 9B4D 5754 99AF A53C

With GnuPG installed, run:

    gpg --show-keys --with-fingerprint archivegenocide-signing-key.asc

Only after confirming that full fingerprint, import the public key and verify:

    gpg --import archivegenocide-signing-key.asc
    gpg --verify zero-breach.py.asc zero-breach.py

Verification must succeed using the expected ArchiveGenocide key. A warning
that the key is not certified by your own web of trust is different from a
bad signature; do not ignore a fingerprint mismatch or failed verification.

The expected SHA-256 of zero-breach.py v0.1.8 is:

    74740af20f609f82dc6e50d66f234d0c39a20f516caa35731c2d19c11684ef44

A signature verifies which key signed these exact bytes. It does not establish
that the program has no bugs. A checksum alone is not publisher authentication.
Signatures also do not establish that an older signed release is the latest one.

## Verify the other release content

Download SHA256SUMS.txt and SHA256SUMS.txt.asc from the same release. Verify
the manifest before using its checksums:

    gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt

Then compare the files with the signed manifest (for example,
sha256sum -c SHA256SUMS.txt on Linux, or
shasum -a 256 -c SHA256SUMS.txt on macOS).
The manifest lists the fifteen release-content files, including the optional
requirements file and Candiru rule attribution and licence records. The manifest itself and
the added public key/signatures are not self-listed.

Public verification artifacts are also retained in release-signatures/v0.1.8/.
No private key is stored in this repository or in its project backups.

## Indicator updates are a separate trust path

The manually run scan/update-iocs.py still checks HTTPS, a published SHA-256,
and indicator-file validity. It does not automatically verify GPG signatures.
The signed release manifest covers the indicator file shipped with v0.1.8;
it does not authenticate later files fetched from the development branch.

## Maintainer release procedure

Use the existing ArchiveGenocide release key only through its configured
keyring. Never export a private key into this project, GitHub, a chat, or logs.
For each new version, first finish and test the immutable release artifacts,
then create detached signatures for its scanner and checksum manifest.
Verify with a separate keyring containing only the published public key;
confirm that a modified-file fixture is rejected.

Publish the matching files and signatures, update the pinned release/hash on
the ArchiveGenocide page, invalidate only affected cached URLs, and verify
fresh public downloads. Keep the release tag and tested scanner bytes unchanged
when adding signatures to an existing release.
