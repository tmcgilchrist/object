(** Common aliases to make more explicit the nature of values being read. *)

type s8   = int
type u8   = int
type u16  = int
type s32  = int
type u32  = int
type u64  = int64
type i64  = int64
type s128 = int (* Ahem, we don't expect 128 bits to really consume 128 bits *)
type u128 = int

(* The sizes of these seems wrong, int is 63 bits on a 64bit system. *)
(* TODO https://github.com/yeslogic/fathom-experiments/tree/main/packages/sized-numbers
https://github.com/ocaml/ocaml/pull/13890 *)