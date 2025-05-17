open Types

(** Low-level buffer manipulation backed by [Bigarray.Array1.t]. *)

type t =
  (int, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

(** Create buffer from filename. *)
val parse : string -> t

(* TODO
   Size of buffer remains int, because the size (aka dim) of
   Bigarray.Array1 is int, not int64. It should be enough in practice,
   as we will not be able to manipulate larger binaries anyway. *)

(** Size of the buffer *)
val size     : t -> int

(** Minimal support for error reporting. FIXME: Exceptions as errors are disappointing. *)
exception Invalid_format of string
val invalid_format : string -> 'a

type cursor = {
  buffer: t;
  mutable position: int;
}

val cursor  : ?at:int -> t -> cursor
val seek    : cursor -> int -> unit
val ensure  : cursor -> int -> string -> unit
val advance : cursor -> int -> unit
val at_end  : cursor -> bool

(** [sub t len] returns a fresh cursor pointing to the
    beginning of a sub-buffer of size [len] starting from [t], and
    advances [t] by [len] *)
val sub     : cursor -> int -> cursor

module Read : sig
  val s8      : cursor -> s8
  val u8      : cursor -> u8
  val u16     : cursor -> u16
  val u32     : cursor -> u32
  val u32be   : cursor -> u32
  val u64     : cursor -> u64
  val i64     : cursor -> i64
  val uleb128 : cursor -> u128
  val sleb128 : cursor -> s128

  (** [fixed_string t len] reads a string of exactly [len] bytes from [t] *)
  val fixed_string : cursor -> int -> string

  (** [zero_string t ?maxlen ()] reads a zero-terminated string from [t],
      stopping at the first zero or when [maxlen] is reached, if it was provided. *)
  val zero_string : cursor -> ?maxlen:int -> unit -> string option

  val buffer : cursor -> int -> t
end
