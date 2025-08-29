open Types

(** Generic abstraction over ELF and Mach-O object file formats *)

(** Architecture types *)
type arch = [ `X86 | `X86_64 | `ARM | `ARM64 | `POWERPC | `POWERPC64 | `Unknown of int ]

(** File format types *)
type format = ELF | MACHO

(** Generic section representation *)
type section = {
  name : string;
  size : u64;
  address : u64;
  offset : u64 option; (** File offset, if available *)
  section_type : string; (** Format-specific type description *)
}

(** Generic segment representation *)
type segment = {
  name : string;
  virtual_address : u64;
  virtual_size : u64;
  file_offset : u64;
  file_size : u64;
  sections : section array;
}

(** Generic header information *)
type header = {
  format : format;
  architecture : arch;
  entry_point : u64 option;
  is_executable : bool;
  is_64bit : bool;
}

(** Object file representation *)
type t = {
  header : header;
  segments : segment array;
  all_sections : section array;
}

(** Parse an object file from a buffer *)
val read : Buffer.t -> t

(** Get all sections from the object file *)
val sections : t -> section array

(** Get all segments from the object file *)
val segments : t -> segment array

(** Find a section by name *)
val find_section : t -> string -> section option

(** Find a segment by name *)
val find_segment : t -> string -> segment option

(** Read section contents *)
val section_contents : Buffer.t -> t -> section -> Buffer.t

(** Get format-specific information *)
val format : t -> format
val architecture : t -> arch
val is_64bit : t -> bool
val is_executable : t -> bool