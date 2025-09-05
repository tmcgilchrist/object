(** Interface for reading object files *)

module Buffer = Buffer
(** Common memory-mapped buffer for reading and writing object files. *)

module Macho = Macho
(** Low-level Mach-O file format *)

module Elf = Elf
(** Low-level ELF file format *)

module Format = Object_format
(** Generic abstraction over ELF and Mach-O file formats *)

module Types = Types
(** Common type definitions *)
