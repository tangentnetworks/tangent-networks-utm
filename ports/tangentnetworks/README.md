<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks

SPDX-License-Identifier: BSD-3-Clause
-->

## **OpenBSD Custom Ports Collection**

## Overview

This repository contains a small collection of **custom OpenBSD ports** that are not (yet) part of the official OpenBSD Ports Tree.
Each directory mirrors the structure used in `/usr/ports`, allowing these ports to be copied or symlinked directly into the tree on any OpenBSD system.

The primary purpose of this collection is:

* Preservation of custom or third-party ports
* Easier sharing, forking, and collaboration
* Tracking updates, patches, and fixes independently of the base system
* Reproducible building of ports across machines

## Repository Layout

Ports are stored in a simplified subset of the official OpenBSD ports hierarchy:

```
openbsd/
└── ports/
    └── security/
        └── snortsentry/
            ├── Makefile
            ├── distinfo
            ├── pkg/
            │   ├── DESCR
            │   └── PLIST
            ├── patches/
            └── files/
```

Each port directory contains only the required files:

* **Makefile**
* **distinfo** (checksums and sizes)
* **pkg/DESCR**, **pkg/PLIST**
* **patches/** (if needed)
* **files/** (for auxiliary scripts or configs)

The repository intentionally does **not** contain:

* `work/` or build artifacts
* packages (`*.tgz`)
* logs
* temporary editor files

## Using These Ports

### 1. Clone the repository

```
git clone https://gitlab.com/tangentnetworks/openbsd-ports.git
```

### 2. Copy a port into the OpenBSD ports tree

```
cd openbsd-ports/openbsd/ports/security/snortsentry
doas cp -R snortsentry /usr/ports/security/
```

Or symlink if preferred:

```
doas ln -s /path/to/openbsd-ports/openbsd/ports/security/snortsentry \
    /usr/ports/security/snortsentry
```

### 3. Build the port

```
cd /usr/ports/security/snortsentry
make install
```

or:

```
make package
```

## Conventions and Notes

* The ports follow OpenBSD guidelines wherever applicable.
* Naming of archives, tags, and distfiles respects upstream conventions to ensure stable checksums.
* All ports are maintained in a clean state — no build output is ever committed.

If a port becomes eligible for submission to the official OpenBSD tree, this repository serves as a staging area for review and testing.

## Contributing

If you wish to contribute:

1. Follow the directory hierarchy:
   `openbsd/ports/<category>/<portname>`
2. Ensure the port builds cleanly with `make package`
3. Include a clear commit message describing changes
4. Do not commit `work/` or `packages/`

Patches and pull requests are welcome.

## License

Unless stated otherwise, ports and supporting material in this repository are provided under the same terms as the upstream software they package.
All metadata (Makefiles, patches, etc.) is released under a permissive license to encourage reuse.




