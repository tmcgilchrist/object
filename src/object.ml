(** Interface for reading object files *)

module Buffer = Buffer
(** Common memory-mapped buffer for reading and writing object files. *)

module Macho = Macho
(** Low-level Mach-O file format *)

module Elf = Elf
(** Low-level ELF file format *)

module Object_format = Object_format
(** Generic abstraction over ELF and Mach-O file formats *)

module Object_types = Object_types
(** Common type definitions *)
