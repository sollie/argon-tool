# argon-tool

Argon2 password hash CLI — generate PHC hashes and verify passwords against them.

## Build

```sh
cargo build --release
# binary at target/release/argon-tool
```

## Usage

### Generate

Bare invocation defaults to generate. Password entered via hidden prompt.

```sh
argon-tool
# Enter Password: ****
# $argon2id$v=19$m=65536,t=4,p=1$<salt>$<hash>
```

Explicit subcommand with flags:

```sh
argon-tool generate --algorithm argon2id --memory 65536 --iterations 4 --parallelism 1
```

Short flags:

```sh
argon-tool generate -a argon2id -m 65536 -t 4 -p 1
```

Environment variables:

```sh
ARGON2_ALGORITHM=argon2id ARGON2_MEMORY=65536 ARGON2_ITERATIONS=4 ARGON2_PARALLELISM=1 argon-tool
```

Supported algorithms: `argon2d`, `argon2i`, `argon2id` (default).

Exits `0` on success, `2` on operational error (e.g. invalid params via env vars).

### Verify — single

```sh
argon-tool verify --hash '$argon2id$v=19$m=65536,t=4,p=1$<salt>$<hash>'
# Enter Password: ****
# MATCH
```

Exit code `0` = match, `1` = mismatch, `2` = operational error (bad PHC, I/O failure).

### Verify — batch from file

File format: one entry per line, `<hash><SEP><password>`. Default separator is TAB.
Hash is always first; password may contain anything (including the separator).
Blank lines are skipped. Lines without a separator are errors.

```sh
argon-tool verify --file hashes.tsv
# line 1: MATCH
# line 2: NO MATCH
# 1/2 matched
```

Custom separator (must not appear in PHC output — avoid `$`, `=`, `,`, base64 alphabet):

```sh
argon-tool verify --file hashes.txt --separator '|'
```

Example file (`hashes.tsv`, TAB-separated):

```
$argon2id$v=19$m=65536,t=4,p=1$abc123$xyz789	correct-password
$argon2id$v=19$m=65536,t=4,p=1$def456$uvw012	wrong-password
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Match (or all batch lines matched) |
| 1 | Mismatch — hash valid, password wrong (or ≥1 batch line mismatched) |
| 2 | Operational error — bad PHC, file not found, malformed line, invalid separator |

Batch precedence (worst outcome wins): `2` > `1` > `0`.

Verification results go to stdout; operational errors go to stderr.
