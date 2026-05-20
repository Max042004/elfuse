# Vendored zstd (decode-only)

This directory contains a decode-only subset of [zstd](https://github.com/facebook/zstd),
the streaming compression library from Facebook. Phase 2 needs zstd to
decompress OCI image layers that ship with `application/vnd.oci.image.layer.v1.tar+zstd`
or `application/vnd.docker.image.rootfs.diff.tar.zstd` media types.

Licensed under BSD-3-Clause (see `LICENSE`).

## Why vendored, decode-only

`oci-roadmap.md` Q9 commits the OCI work to hand-rolled C: no Go, no Rust,
no `cargo` / `go` in the build matrix. zstd is the only OCI-spec layer
compression beyond gzip that has wide registry support, and the upstream
library cleanly separates decoder-only from the full encoder. Phase 2 only
reads layers, so the encoder, dictionary builder, and legacy v01-v06
support are all excluded.

Resulting footprint:

- `lib/{zstd,zstd_errors}.h`
- `lib/common/*.{c,h}` (allocator, error tables, FSE/Huff decoders,
  threading stubs, xxhash, portability shims)
- `lib/decompress/*.{c,h}` (the streaming decode state machine)

Compression, dictBuilder, deprecated, and legacy paths are NOT vendored.
Do not call `ZSTD_compress*`, `ZDICT_*`, or any `ZSTD_v0X_*` symbol.

## Version

Pinned to upstream tag `v1.5.6` (2024-03-30). Fetched with:

```
curl -fsSL -o zstd-v1.5.6.tar.gz \
    https://github.com/facebook/zstd/archive/refs/tags/v1.5.6.tar.gz
tar -xzf zstd-v1.5.6.tar.gz
SRC=zstd-1.5.6
cp $SRC/LICENSE externals/zstd/LICENSE
cp $SRC/lib/zstd.h $SRC/lib/zstd_errors.h externals/zstd/lib/
cp $SRC/lib/common/*.[ch] externals/zstd/lib/common/
cp $SRC/lib/decompress/*.[ch] externals/zstd/lib/decompress/
```

Note: `lib/decompress/huf_decompress_amd64.S` is intentionally NOT
copied. The build sets `-DZSTD_DISABLE_ASM=1` so `huf_decompress.c`
references no AMD64 assembly symbols; the elfuse host is Apple Silicon
in any case.

## Local modifications

None. The files are byte-identical to the upstream tag so future
security updates can be applied by re-running the curl + cp commands
above.

## Build integration

The Makefile compiles each `externals/zstd/lib/**/*.c` translation unit
with project warning flags relaxed (`-Wno-pedantic -Wno-shadow
-Wno-strict-prototypes -Wno-missing-prototypes`) and with the
configuration macros:

```
-DZSTD_DISABLE_ASM=1
-DZSTD_LEGACY_SUPPORT=0
-DZSTD_MULTITHREAD=0
-DZSTDLIB_VISIBILITY=
```

Only `src/oci/decompress.c` includes `externals/zstd/lib/zstd.h`; the
rest of the codebase never sees zstd headers. The zstd objects are
statically embedded into the `elfuse` binary, so no `-lzstd` link line
is needed.
