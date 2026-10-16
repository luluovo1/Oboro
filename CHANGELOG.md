# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Entries are tracked from the current documentation overhaul onward; earlier history lives in the commit log and [Releases](https://github.com/luluovo1/Oboro/releases).

## [Unreleased]

### Added

- Departure notice: this repository will gradually detach from LLVM upstream and KomiMoe/Arkari, moving to an independent branch line with its own obfuscation algorithms and implementation logic
- Bilingual documentation with English as the default: `README.zh-CN.md`, `USAGE_en.md`, `CONTRIBUTING.zh-CN.md`
- `CONTRIBUTING.md` (contributing guide), `CHANGELOG.md`, security reporting policy in `SECURITY.md`
- Star history chart in the README

### Changed

- README restructured: keeps only intro / quick start / differences / best practices; the flag quick reference and before/after obfuscation comparisons moved to `USAGE.md`
- Language switch buttons added to README and USAGE; English is the default entry
- License badge now links to the repository's `LICENSE.TXT`

### Removed

- Broken references to the non-existent `testresu/` directory in README and USAGE

## [ndk-r30-with-ollvm] - 2026-03-23

### Added

- Initial public release: a custom-built Android NDK r30 toolchain with the Arkari obfuscator integrated (`android-ndk-r30-windows-x86_64-arkari.zip`), plus an unmodified official NDK for comparison (`android-ndk-r30-windows-x86_64-official.zip`)

[Unreleased]: https://github.com/luluovo1/Oboro/compare/ndk-r30-with-ollvm...HEAD
[ndk-r30-with-ollvm]: https://github.com/luluovo1/Oboro/releases/tag/ndk-r30-with-ollvm
