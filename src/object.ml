(** Interface for reading object files *)

module Buffer = Buffer
(** Common memory-mapped buffer for reading and writing object files. *)

module Macho = Macho
(** Low-level Mach-O file format *)

module Elf = Elf
(** Low-level ELF file format *)

module Pe = Pe
(** Low-level PE/COFF file format *)

module Format = Object_format
(** Generic abstraction over ELF, Mach-O, and PE file formats *)

module Types = Types
(** Common type definitions *)
