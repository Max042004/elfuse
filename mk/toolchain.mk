# Compiler and toolchain detection

MAKEFLAGS += --no-builtin-rules --no-builtin-variables

# Primary compiler. GNU make predefines CC=cc, so replace only that
# default while preserving explicit user/environment overrides.
ifeq ($(origin CC),default)
  CC := clang
else
  CC ?= clang
endif

# GNU objcopy for Mach-O / ELF -> raw binary
ifdef GNU_OBJCOPY
  OBJCOPY := $(GNU_OBJCOPY)
else ifneq ($(wildcard /opt/homebrew/opt/binutils/bin/objcopy),)
  OBJCOPY ?= /opt/homebrew/opt/binutils/bin/objcopy
else
  OBJCOPY ?= llvm-objcopy
endif

# Bare-metal aarch64 ELF toolchain for assembly tests
ELF_TOOLCHAIN ?= /opt/toolchain/aarch64-none-elf
ifneq ($(wildcard $(ELF_TOOLCHAIN)/bin/aarch64-none-elf-as),)
  BAREMETAL_CROSS ?= $(ELF_TOOLCHAIN)/bin/aarch64-none-elf-
else
  BAREMETAL_CROSS ?= aarch64-none-elf-
endif

# Linux cross-compiler (for guest test binaries when
# GUEST_TEST_BINARIES is unset)
LINUX_TOOLCHAIN ?= /opt/toolchain/aarch64-linux-gnu
ifneq ($(wildcard $(LINUX_TOOLCHAIN)/bin/aarch64-linux-gnu-gcc),)
  CROSS_COMPILE ?= $(LINUX_TOOLCHAIN)/bin/aarch64-linux-gnu-
else
  CROSS_COMPILE ?= aarch64-linux-gnu-
endif

# Shim assembler (defaults to Apple's assembler)
SHIM_AS ?= as
SHIM_ASFLAGS ?= -arch arm64

# clang-format
CLANG_FORMAT ?= clang-format

# OpenSSL (Homebrew) for the OCI fetch test scaffolding. The mock HTTP server
# uses libssl/libcrypto to terminate TLS with a self-signed certificate so the
# ca_file negative cases exercise a real handshake. macOS ships LibreSSL
# headers in a private framework and does not publish a usable include path
# under /usr; brew openssl@3 is the documented public location.
ifeq ($(origin OPENSSL_PREFIX),undefined)
  ifneq ($(wildcard /opt/homebrew/opt/openssl@3/include/openssl/ssl.h),)
    OPENSSL_PREFIX := /opt/homebrew/opt/openssl@3
  else ifneq ($(wildcard /usr/local/opt/openssl@3/include/openssl/ssl.h),)
    OPENSSL_PREFIX := /usr/local/opt/openssl@3
  else
    OPENSSL_PREFIX :=
  endif
endif
ifneq ($(OPENSSL_PREFIX),)
  OPENSSL_CFLAGS  := -I$(OPENSSL_PREFIX)/include
  OPENSSL_LDFLAGS := -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
else
  OPENSSL_CFLAGS  :=
  OPENSSL_LDFLAGS := -lssl -lcrypto
endif
