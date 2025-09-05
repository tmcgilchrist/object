(** Common aliases to make more explicit the nature of values being read. *)

type s8 = Signed.Int8.t
type u8 = Unsigned.UInt8.t
type u16 = Unsigned.UInt16.t
type s32 = Signed.Int32.t
type u32 = Unsigned.UInt32.t
type u64 = Unsigned.UInt64.t
type i64 = Signed.Int64.t
type s128 = int (* Ahem, we don't expect 128 bits to really consume 128 bits *)
type u128 = int

(* The sizes of these seems wrong, int is 63 bits on a 64bit system. *)
(* TODO https://github.com/yeslogic/fathom-experiments/tree/main/packages/sized-numbers
   https://github.com/ocaml/ocaml/pull/13890
   https://github.com/andrenth/ocaml-stdint
 *)
