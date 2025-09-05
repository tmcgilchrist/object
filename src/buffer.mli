open Types

(** Low-level buffer manipulation backed by [Bigarray.Array1.t]. *)

type t = (int, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

val parse : string -> t
(** Create buffer from filename. *)

(* TODO
   Size of buffer remains int, because the size (aka dim) of
   Bigarray.Array1 is int, not int64. It should be enough in practice,
   as we will not be able to manipulate larger binaries anyway. *)

val size : t -> int
(** Size of the buffer *)

exception Invalid_format of string
(** Minimal support for error reporting. FIXME: Exceptions as errors are
    disappointing. *)

val invalid_format : string -> 'a
(** Raise [Invalid_format] exception with a msg. *)

type cursor = { buffer : t; mutable position : int }
(** A cursor for reading data sequentially from a buffer. The cursor maintains a
    reference to the underlying buffer and tracks the current position. *)

val cursor : ?at:int -> t -> cursor
(** [cursor ?at buffer] creates a new cursor for the given buffer. The cursor
    starts at position [at] (default: 0). *)

val seek : cursor -> int -> unit
(** [seek cursor pos] moves the cursor to the absolute position [pos] in the
    buffer. *)

val ensure : cursor -> int -> string -> unit
(** [ensure cursor len msg] verifies that at least [len] bytes are available
    from the current cursor position. Raises [Invalid_format msg] if
    insufficient data. *)

val advance : cursor -> int -> unit
(** [advance cursor len] moves the cursor forward by [len] bytes. *)

val at_end : cursor -> bool
(** [at_end cursor] returns [true] if the cursor is at the end of the buffer. *)

val sub : cursor -> int -> cursor
(** [sub cursor len] returns a fresh cursor pointing to the beginning of a
    sub-buffer of size [len] starting from [cursor], and advances [cursor] by
    [len] bytes. *)

module Read : sig
  (** Functions for reading binary data from cursors in little-endian format. *)

  val s8 : cursor -> s8
  (** [s8 cursor] reads a signed 8-bit integer and advances the cursor by 1
      byte. *)

  val u8 : cursor -> u8
  (** [u8 cursor] reads an unsigned 8-bit integer and advances the cursor by 1
      byte. *)

  val u16 : cursor -> u16
  (** [u16 cursor] reads an unsigned 16-bit integer (little-endian) and advances
      the cursor by 2 bytes. *)

  val u32 : cursor -> u32
  (** [u32 cursor] reads an unsigned 32-bit integer (little-endian) and advances
      the cursor by 4 bytes. *)

  val u32be : cursor -> u32
  (** [u32be cursor] reads an unsigned 32-bit integer (big-endian) and advances
      the cursor by 4 bytes. *)

  val u64 : cursor -> u64
  (** [u64 cursor] reads an unsigned 64-bit integer (little-endian) and advances
      the cursor by 8 bytes. *)

  val i64 : cursor -> i64
  (** [i64 cursor] reads a signed 64-bit integer (little-endian) and advances
      the cursor by 8 bytes. *)

  val uleb128 : cursor -> u128
  (** [uleb128 cursor] reads an unsigned LEB128 (Little Endian Base 128) encoded
      integer and advances the cursor by the appropriate number of bytes. *)

  val sleb128 : cursor -> s128
  (** [sleb128 cursor] reads a signed LEB128 (Little Endian Base 128) encoded
      integer and advances the cursor by the appropriate number of bytes. *)

  val fixed_string : cursor -> int -> string
  (** [fixed_string cursor len] reads a string of exactly [len] bytes from
      [cursor] and advances the cursor by [len] bytes. *)

  val zero_string : cursor -> ?maxlen:int -> unit -> string option
  (** [zero_string cursor ?maxlen ()] reads a zero-terminated string from
      [cursor], stopping at the first zero byte or when [maxlen] is reached, if
      provided. Returns [None] if no zero terminator is found within [maxlen]
      bytes. Advances the cursor past the zero terminator or by [maxlen] bytes.
  *)

  val buffer : cursor -> int -> t
  (** [buffer cursor len] extracts a sub-buffer of [len] bytes starting from the
      cursor's current position and advances the cursor by [len] bytes. *)
end
