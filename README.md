# `object`

The `object` package provides a unified interface for working with object files
across platforms. It supports reading relocatable object files and executable files,
and writing COFF/ELF/Mach-O/XCOFF relocatable object files and ELF/PE/Mach-O
executable files.

For reading files the library provides various abstraction levels:

 * raw type/record definitions close to the original C definitions
 * low level APIs for accessing specific formats
 * a higher level unified API for accessing common features of object files,
   such as sections and symbols

Supported file formats for reading: ELF, Macho-O, Windows PE/COFF, and Unix Archive.

For writing files the library provides:

 * low level writers for ELF, Mach-O, and PE/COFF.
 * higher level builder for ELF
 * a unified API for writing relocatable object files (ELF, Mach-O, COFF)

## Prior work

This motivation for this library grew out of the author's need to manipulate object
files and DWARF information while working on the OCaml compiler. The library name
simultaneously derives from the author's fascination with objects in OCaml and the
[Rust library](https://github.com/gimli-rs/object) of the same name.