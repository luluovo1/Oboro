# Security Policy

## Reporting a Vulnerability

Please do **not** report security vulnerabilities through public GitHub Issues.

To report a vulnerability privately, use GitHub's private reporting: go to the **Security** tab of this repository and click **Report a vulnerability**.

We will acknowledge your report as soon as possible and keep you informed of the fix progress.

## Scope

This repository ships a compiler toolchain (an LLVM/NDK-based obfuscator). Security-relevant reports include, but are not limited to:

- Flaws that let obfuscated output be trivially reversed or de-obfuscated
- Bugs causing the toolchain to emit incorrect or insecure code
- Issues that could leak sensitive information from builds
