# Unreleased
- #12: Read symbol names without moving the symbol table cursor
- #15: Bounds-check every `Buffer.Read` function, raising `Invalid_format`
  instead of `Invalid_argument`. Also reject negative positions, LEB128 values
  that don't fit in an `int`, and read `u32be` as big-endian
- #16: Reject `uleb128` values of 2^62 and above, which were returned as
  negative `int`s. Add hedgehog property tests for LEB128 decoding
- #17: Check table counts against the remaining data before allocating. A
  corrupt Mach-O, ELF or PE count raises `Invalid_format` instead of trying to
  allocate gigabytes. `Macho.validate_fat` checks overlaps between neighbouring
  architectures only, avoiding a quadratic error list
- #18: Reject Mach-O load commands whose `cmdsize` is smaller than the
  command's fixed-size structure, raising `Invalid_format` from `Macho.read`
- #19: Check section and fat architecture extents against the buffer, raising
  `Invalid_format` instead of `Invalid_argument`. ELF `SHT_NOBITS` sections,
  Mach-O zero-fill sections and Mach-O sections at offset 0 (as in a dSYM) now
  have no file contents (`file_size` 0, empty body) instead of reading
  unrelated bytes. Add `Elf.has_file_data` and `Macho.has_file_data`
- #20: Read ELF files without a section header table or section name string
  table (`e_shstrndx` of `SHN_UNDEF`), and resolve extended section numbering
  (`SHN_XINDEX`). An out-of-range `e_shstrndx`, an `e_shentsize` other than 64
  or a section count past the end of the file raises `Invalid_format`
- #21: Raise `Invalid_format` instead of `Failure` for unsupported ELF classes
  and data encodings and for unrecognised formats in
  `Object_format.detect_format`. Reject big-endian ELF explicitly instead of
  misreading it. `Object_format.Invalid_format` is now the same exception as
  `Buffer.Invalid_format`. `Object_format` detects bare COFF objects as `PE`
- #22: Fix Mach-O load command offsets. Dylib, dylinker, sub-framework and
  prebound dylib names lost their first 8 bytes, `LC_RPATH` paths were read
  from the start of the file, and `LC_TWOLEVEL_HINTS` read its table from the
  command instead of the file. `LC_PREBOUND_DYLIB` reads `(n + 7) / 8` bytes of
  module bit vector
- #23: `Macho.read` and `Object_format.read` raise an `Invalid_format` naming
  the functions that select an architecture when given a FAT binary, instead
  of failing with "magic"

# 0.1

Initial release supporting ELF/MACH-O/PE/COFF object files
