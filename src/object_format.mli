open Object_types

(** Generic abstraction over ELF and Mach-O object file formats *)

exception Invalid_format of string
(** Exception raised when file format is invalid or unsupported *)

type arch =
  [ `X86 | `X86_64 | `ARM | `ARM64 | `POWERPC | `POWERPC64 | `Unknown of int ]
(** Architecture types *)

(** File format types *)
type format = ELF | MACHO | PE

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

val detect_format : Buffer.t -> format
(** Detect file format from buffer using magic numbers *)

(** {2 Multi-Architecture Support} *)

val is_fat : Buffer.t -> bool
(** [is_fat buffer] checks if the buffer contains a FAT/Universal binary.

    @param buffer The buffer to check
    @return true if FAT binary, false otherwise *)

val list_archs : Buffer.t -> string array
(** [list_archs buffer] returns the list of architecture names in a FAT binary.

    @param buffer The FAT binary buffer
    @return Array of architecture names (e.g. ["x86_64"; "arm64e"])
    @raise Invalid_format if not a FAT binary *)

val read_arch : Buffer.t -> string -> t
(** [read_arch buffer arch_name] reads a specific architecture from a FAT
    binary.

    @param buffer The FAT binary buffer
    @param arch_name The architecture name to read
    @return Parsed object file for that architecture
    @raise Invalid_format if not a FAT binary or architecture not found *)

val iter_archs : Buffer.t -> (string -> t -> unit) -> unit
(** [iter_archs buffer f] iterates over all architectures in a FAT binary,
    calling [f arch_name obj] for each one.

    @param buffer The FAT binary buffer
    @param f Function to call for each architecture
    @raise Invalid_format if not a FAT binary *)
