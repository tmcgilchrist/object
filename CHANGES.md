# Unreleased
- #12: Read symbol names without moving the symbol table cursor
- #???: Bounds-check every `Buffer.Read` function, raising `Invalid_format`
  instead of `Invalid_argument`. Also reject negative positions, LEB128 values
  that don't fit in an `int`, and read `u32be` as big-endian

# 0.1

Initial release supporting ELF/MACH-O/PE/COFF object files
