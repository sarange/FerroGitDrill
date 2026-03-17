# FerroGitDrill

A tool for recovering git repositories from exposed .git directories on web servers.

## Installation

You need Rust and Cargo installed. Clone this repo and build the binary:

```bash
cargo build --release
```

The binary will be available at `target/release/ferro-git-drill`.

## Usage

Reconstruct a repository from a single URL:

```bash
./ferro-git-drill --url https://example.com/.git --output ./recovered_repo
```

Batch process multiple targets from a file:

```bash
./ferro-git-drill --list targets.txt --output ./all_recoveries
```

Use `--help` to see all available flags for proxy settings, concurrent jobs, and custom headers.

## How it works

The tool checks if directory listing is enabled for the .git folder. If it is, it performs a recursive download. If listing is disabled, it uses a list of common git files and references to find as many objects as possible. It then parses commit and tree objects to find missing pieces and finally runs a checkout to restore the working tree.

## Inspiration

- [git-dumper](https://github.com/arthaud/git-dumper)

## License

GPLv3. See the LICENSE file for details.
