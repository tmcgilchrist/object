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

# 0.1

Initial release supporting ELF/MACH-O/PE/COFF object files
