# Contributing to Nyx

First off, **thank you for taking the time to contribute!** By participating in this project, you agree to abide by the community values and expectations described in our [Code of Conduct](CODE_OF_CONDUCT.md).

Nyx is dual‑licensed under **MIT** and **Apache‑2.0**. By submitting code, documentation, or any other material, you agree to license your contribution under these same terms.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [How to Contribute](#how-to-contribute)

    * [Bug Reports](#bug-reports)
    * [Feature Requests](#feature-requests)
    * [Pull Requests](#pull-requests)
3. [Development Workflow](#development-workflow)
4. [Commit & Branching Conventions](#commit--branching-conventions)
5. [Style Guide](#style-guide)
6. [Security Policy](#security-policy)
7. [Community Standards](#community-standards)

---

## Getting Started

Clone the repository and build Nyx in release mode:

```bash
git clone https://github.com/<your‑org>/nyx.git
cd nyx
cargo build --release
```

Run the test‑suite:

```bash
cargo test
```

> **Tip**: The first build downloads and compiles several `tree‑sitter` grammars. Later builds will be faster.

---

## How to Contribute

### Bug Reports

* Search existing [issues](https://github.com/<your‑org>/nyx/issues) to ensure the bug has not already been reported.
* Include **steps to reproduce**, expected vs. actual behaviour, and your environment details (`nyx --version`, `rustc --version`).
* Attach a minimal code sample if possible.

### Feature Requests

We welcome well‑motivated feature proposals. Please describe:

1. **Problem statement** – what pain point does this solve?
2. **Proposed solution** – high‑level description, optionally with pseudo‑code.
3. **Alternatives considered** – why existing functionality is not enough.

### Pull Requests

Every PR should:

1. Target the `main` branch.
2. Contain a single, focused change (small orthogonal fixes are okay).
3. Pass `cargo test`, `cargo fmt --check`, and `cargo clippy -- -D warnings`.
4. Update documentation and, when relevant, add tests.
5. Reference related issue numbers in the description (`Fixes #123`).

A reviewer will provide feedback within **3 business days**. Squash‑merge is the default strategy; maintainers may edit commit messages for clarity.

---

## Development Workflow

1. **Fork** the repo and create your feature branch:

   ```bash
   git checkout -b feature/my‑feature
   ```

2. Make your changes, then run:

   ```bash
   cargo fmt
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test
   ```

3. **Sign‑off** your commits if your employer requires a Developer Certificate of Origin (DCO):

   ```bash
   git commit -s -m "feat: add XYZ"
   ```

4. Push the branch and open a PR against `main`.

---

## Commit & Branching Conventions

* **Branch names**: `feature/<slug>`, `fix/<slug>`, `docs/<slug>`
* **Commit style** – Conventional Commits (simplified):

  ```text
  type(scope): subject

  body (optional)
  ```

  | Type       | Use for                              |
  |------------|--------------------------------------|
  | `feat`     | New functionality                    |
  | `fix`      | Bug fixes                            |
  | `docs`     | Documentation only                   |
  | `refactor` | Code change without behaviour change |
  | `test`     | Adding or changing tests             |
  | `chore`    | Build process, tooling               |

---

## Style Guide

* **Formatting**: run `cargo fmt` before committing.
* **Linting**: CI runs Clippy with `-D warnings`; keep the tree warning‑free.
* **Unsafe Rust**: prohibited unless absolutely necessary. Justify with in‑code comments.
* **Public API stability**: avoid breaking changes on exported types and functions without prior discussion.

---

## Security Policy

Please do **not** open public issues for security‑sensitive bugs. Instead, email the maintainers at `<security@example.com>` with the details and a proof of concept. We aim to acknowledge reports within **48 hours**.

---

## Community Standards

We strive to maintain a welcoming and inclusive community. Harassment, discrimination, or other forms of unacceptable behavior will be addressed per the [Code of Conduct](CODE_OF_CONDUCT.md).

Thank you for helping to make Nyx better!
