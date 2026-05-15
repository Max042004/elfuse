# Vendored cJSON

This directory contains a vendored copy of [cJSON](https://github.com/DaveGamble/cJSON),
the ultralightweight JSON parser written in ANSI C. cJSON ships as a single
`.c` / `.h` pair and is dual-licensed under the MIT license (see `LICENSE`).

## Why vendored

`oci-roadmap.md` Q9 commits Phase 1 to hand-rolled C alongside the existing
elfuse codebase: no Go, no Rust, no `cargo` / `go` in the build matrix. cJSON
is the smallest credible JSON dependency that fits that contract; it is
self-contained, has no external dependencies, and compiles cleanly with
`clang` and `gcc` on macOS and Linux.

## Version

Pinned to upstream tag `v1.7.18` (2024-07-30). Fetched with:

```
curl -fsSL -o cJSON.h https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.18/cJSON.h
curl -fsSL -o cJSON.c https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.18/cJSON.c
curl -fsSL -o LICENSE https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.18/LICENSE
```

## Local modifications

None. The files are byte-identical to the upstream tag so future security
updates can be applied by re-running the curl commands above.

## Build integration

The Makefile compiles `cJSON.c` with project warning flags relaxed: cJSON is
third-party code and its style does not match elfuse's `-Wpedantic
-Wmissing-prototypes -Wshadow` posture. Only `src/oci/` translation units
include `externals/cjson/cJSON.h`; the rest of the codebase never sees it.
