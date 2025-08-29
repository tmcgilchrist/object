open Types

(** Generic abstraction over ELF and Mach-O object file formats *)

type arch =
  [ `X86 | `X86_64 | `ARM | `ARM64 | `POWERPC | `POWERPC64 | `Unknown of int ]
(** Architecture types *)

(** File format types *)
type format = ELF | MACHO

type section = {
  name : string;
  size : u64;
  address : u64;
  offset : u64 option;  (** File offset, if available *)
  section_type : string;  (** Format-specific type description *)
}
(** Generic section representation *)

type segment = {
  name : string;
  virtual_address : u64;
  virtual_size : u64;
  file_offset : u64;
  file_size : u64;
  sections : section array;
}
(** Generic segment representation *)

type header = {
  format : format;
  architecture : arch;
  entry_point : u64 option;
  is_executable : bool;
  is_64bit : bool;
}
(** Generic header information *)

type t = {
  header : header;
  segments : segment array;
  all_sections : section array;
}
(** Object file representation *)

val read : Buffer.t -> t
(** Parse an object file from a buffer *)

val sections : t -> section array
(** Get all sections from the object file *)

val segments : t -> segment array
(** Get all segments from the object file *)

val find_section : t -> string -> section option
(** Find a section by name *)

val find_segment : t -> string -> segment option
(** Find a segment by name *)

val section_contents : Buffer.t -> t -> section -> Buffer.t
(** Read section contents *)

val format : t -> format
(** Get format-specific information *)

val architecture : t -> arch
val is_64bit : t -> bool
val is_executable : t -> bool
