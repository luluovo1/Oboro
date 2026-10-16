# Contributing Guide

[English](./CONTRIBUTING.md) | [简体中文](./CONTRIBUTING.zh-CN.md)

Thanks for your interest in this project! Issues and pull requests are welcome.

## Reporting Issues

Search the existing [Issues](https://github.com/luluovo1/Oboro/issues) before filing a new one. Please include:

- Toolchain version (Release tag or commit)
- Host platform (Windows / Linux / macOS) and target ABI
- Minimal reproduction steps and obfuscation flags
- Expected vs. actual behavior
- Relevant logs, decompilation screenshots, or crash information

## Feature Requests

Open an Issue describing the new obfuscation option or usability improvement, along with the use case and expected benefit.

## Pull Requests

1. Fork this repository and create a feature branch from `main`
2. Keep the change focused: one PR solves one problem
3. For obfuscation pass changes, describe the impact on:
   - Obfuscation strength and reverse-engineering difficulty
   - Runtime performance and binary size overhead
   - Compatibility with existing flag combinations
4. Self-test before submitting: compile at least one example and confirm the obfuscation takes effect and the output runs correctly
5. Link the related Issue in the PR description and attach test results

## Roadmap

- More obfuscation options (new passes / new flags)
- Ongoing evolution of the independent obfuscation algorithms and implementation (this repository is gradually detaching from upstream — see the notice at the top of the README)
- Documentation improvements and multilingual maintenance

## Notes

- Do not submit LLVM upstream sync changes unrelated to obfuscation
- Do not submit code or tutorials intended for illegal purposes
- By contributing, you agree that your code will be released under this repository's license

## License

This project is licensed under LLVM Apache 2.0. See [LICENSE.TXT](./LICENSE.TXT).
