(** Low-level buffer manipulation *)

type t = (int, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t
type cursor = { buffer : t; mutable position : int }

exception Invalid_format of string

let invalid_format msg = raise (Invalid_format msg)

let parse path =
  let fd = Unix.openfile path [ Unix.O_RDONLY ] 0 in
  Fun.protect
    ~finally:(fun () -> Unix.close fd)
    (fun () ->
      let len = Unix.lseek fd 0 Unix.SEEK_END in
      Bigarray.array1_of_genarray
        (Unix.map_file fd Bigarray.int8_unsigned Bigarray.c_layout false
           [| len |]))

let size = Bigarray.Array1.dim
let cursor ?(at = 0) buffer = { buffer; position = at }
let seek t position = t.position <- position

let ensure t count msg =
  (* [new_pos < 0] catches [position + count] overflowing. *)
  let new_pos = t.position + count in
  if t.position < 0 || count < 0 || new_pos < 0 || size t.buffer < new_pos then
    invalid_format msg

let advance t count = t.position <- t.position + count
let at_end t = size t.buffer = t.position

open Object_types

(* All endian and bit-width dependent code starts here *)
module Read = struct
  let u8 t : u8 =
    ensure t 1 "u8: out of bounds";
    let result = t.buffer.{t.position} in
    advance t 1;
    Unsigned.UInt8.of_int result

  let s8 t : s8 =
    ensure t 1 "s8: out of bounds";
    let result = t.buffer.{t.position} in
    advance t 1;
    if result > 0x7F then Signed.Int8.of_int (result lor (-1 lsl 8))
    else Signed.Int8.of_int result

  let u16 t : u16 =
    ensure t 2 "u16: out of bounds";
    let result = t.buffer.{t.position} lor (t.buffer.{t.position + 1} lsl 8) in
    advance t 2;
    Unsigned.UInt16.of_int result

  let u32 t : u32 =
    ensure t 4 "u32: out of bounds";
    let result =
      t.buffer.{t.position}
      lor (t.buffer.{t.position + 1} lsl 8)
      lor (t.buffer.{t.position + 2} lsl 16)
      lor (t.buffer.{t.position + 3} lsl 24)
    in
    advance t 4;
    Unsigned.UInt32.of_int result

  let u32be t : u32 =
    ensure t 4 "u32be: out of bounds";
    let result =
      (t.buffer.{t.position} lsl 24)
      lor (t.buffer.{t.position + 1} lsl 16)
      lor (t.buffer.{t.position + 2} lsl 8)
      lor t.buffer.{t.position + 3}
    in
    advance t 4;
    Unsigned.UInt32.of_int result

  let u64 t : u64 =
    ensure t 8 "u64: out of bounds";
    let result = ref 0L in
    for i = 0 to 7 do
      let open Int64 in
      let n = of_int t.buffer.{t.position + i} in
      result := logor !result (shift_left n (i * 8))
    done;
    advance t 8;
    Unsigned.UInt64.of_int64 !result

  let i64 t : i64 =
    (* u64 are wrapped in an i64 and are actually signed. *)
    Unsigned.UInt64.to_int64 (u64 t)

  (* Nine 7-bit groups fill the 63 bits of an OCaml int. A tenth byte may only
     be redundant padding (0x00) or, for sleb128, sign extension (0x7f). *)
  let uleb128 t : u128 =
    let rec aux t shift acc =
      let x = u8 t |> Unsigned.UInt8.to_int in
      if shift >= 63 then
        if x = 0 then acc else invalid_format "uleb128: value too large"
      else
        let acc = acc lor ((x land 0x7f) lsl shift) in
        if x land 0x80 = 0 then acc else aux t (shift + 7) acc
    in
    aux t 0 0

  let sleb128 t : s128 =
    let rec aux t shift acc =
      let x = u8 t |> Unsigned.UInt8.to_int in
      if shift >= 63 then
        match x with
        | 0x00 when acc >= 0 -> acc
        | 0x7f when acc < 0 -> acc
        | _ -> invalid_format "sleb128: value too large"
      else
        let acc = acc lor ((x land 0x7f) lsl shift) in
        if x land 0x80 <> 0 then aux t (shift + 7) acc
        else if x land 0x40 = 0 || shift + 7 >= 63 then acc
        else acc lor -(1 lsl (shift + 7))
    in
    aux t 0 0

  let fixed_string t length =
    ensure t length "fixed_string: out of bounds";
    let { buffer; position } = t in
    let result = Bytes.create length in
    for i = 0 to length - 1 do
      Bytes.set result i (Char.unsafe_chr buffer.{position + i})
    done;
    advance t length;
    Bytes.unsafe_to_string result

  let rec scan_0 (b : t) ofs l i =
    if i >= l then None
    else if b.{ofs + i} = 0 then Some i
    else scan_0 b ofs l (i + 1)

  let zero_string t ?maxlen () =
    let remaining = max 0 (size t.buffer - t.position) in
    let maxlen =
      match maxlen with
      | None -> remaining
      | Some maxlen -> max 0 (min maxlen remaining)
    in
    match scan_0 t.buffer t.position maxlen 0 with
    | None -> None
    | Some length ->
        let result = fixed_string t length in
        advance t 1;
        Some result

  let buffer t length =
    ensure t length "buffer: out of bounds";
    let result = Bigarray.Array1.sub t.buffer t.position length in
    advance t length;
    result
end

let sub t length = cursor (Read.buffer t length)
