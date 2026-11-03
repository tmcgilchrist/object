open Hedgehog
open Object.Buffer

(* Reference LEB128 encoders over 64-bit values, so the generators can produce
   inputs that don't fit in an OCaml int. *)
let encode_u64 x =
  let rec go x acc =
    let byte = Int64.(to_int (logand x 0x7fL)) in
    let x = Int64.shift_right_logical x 7 in
    if x = 0L then List.rev (byte :: acc) else go x ((byte lor 0x80) :: acc)
  in
  go x []

let encode_s64 x =
  let rec go x acc =
    let byte = Int64.(to_int (logand x 0x7fL)) in
    let x = Int64.shift_right x 7 in
    let sign = byte land 0x40 <> 0 in
    if (x = 0L && not sign) || (x = -1L && sign) then List.rev (byte :: acc)
    else go x ((byte lor 0x80) :: acc)
  in
  go x []

type decoded = Decoded of int * int | Rejected

let show_decoded = function
  | Decoded (v, n) -> Printf.sprintf "Decoded (%d, %d bytes)" v n
  | Rejected -> "Rejected"

let show_bytes bytes =
  String.concat " " (List.map (Printf.sprintf "%02x") bytes)

let decode read bytes =
  let c =
    cursor
      (Bigarray.Array1.of_array Bigarray.int8_unsigned Bigarray.c_layout
         (Array.of_list bytes))
  in
  match read c with
  | v -> Decoded (v, c.position)
  | exception Invalid_format _ -> Rejected

let check_decode read bytes expected =
  Property.annotate (show_bytes bytes);
  Property.diff show_decoded ( = ) show_decoded expected (decode read bytes)

let fits_int x = x >= Int64.of_int min_int && x <= Int64.of_int max_int
let fits_uint x = x >= 0L && fits_int x

(* A value of a random bit width, plus the values either side of the int
   limits, so every encoded length and both rejection edges are covered. *)
let gen_int64 shift =
  let open Gen in
  let edges =
    List.concat_map
      (fun x -> [ Int64.pred x; x; Int64.succ x ])
      [ 0L; Int64.of_int max_int; Int64.of_int min_int; Int64.min_int ]
  in
  frequency
    [
      ( 9,
        let+ bits = int (Range.constant 0 64)
        and+ x = int64 (Range.constant_int64 Int64.min_int Int64.max_int) in
        if bits = 0 then 0L else shift x (64 - bits) );
      (1, element edges);
    ]

let gen_uint =
  Gen.map Int64.to_int
    (Gen.filter fits_uint (gen_int64 Int64.shift_right_logical))

let gen_sint =
  Gen.map Int64.to_int (Gen.filter fits_int (gen_int64 Int64.shift_right))

let uleb128_model =
  Property.property
    Gen.(
      let+ x = gen_int64 Int64.shift_right_logical in
      fun () ->
        let bytes = encode_u64 x in
        Property.classify "rejected" (not (fits_uint x));
        check_decode Read.uleb128 bytes
          (if fits_uint x then Decoded (Int64.to_int x, List.length bytes)
           else Rejected))

let sleb128_model =
  Property.property
    Gen.(
      let+ x = gen_int64 Int64.shift_right in
      fun () ->
        let bytes = encode_s64 x in
        Property.classify "rejected" (not (fits_int x));
        check_decode Read.sleb128 bytes
          (if fits_int x then Decoded (Int64.to_int x, List.length bytes)
           else Rejected))

(* Re-encode the last byte with a continuation bit and append [pad] bytes of
   [fill] followed by [last], keeping within the ten bytes an int needs. *)
let padded bytes ~fill ~last pad =
  match List.rev bytes with
  | [] -> bytes
  | final :: rest ->
      List.rev rest
      @ ((final lor 0x80) :: List.init (pad - 1) (fun _ -> fill))
      @ [ last ]

let gen_pad bytes = Gen.int (Range.constant 1 (10 - List.length bytes))

let uleb128_padding =
  Property.property
    Gen.(
      let* n = gen_uint in
      let bytes = encode_u64 (Int64.of_int n) in
      let+ pad = gen_pad bytes in
      fun () ->
        let bytes = padded bytes ~fill:0x80 ~last:0x00 pad in
        check_decode Read.uleb128 bytes (Decoded (n, List.length bytes)))

let sleb128_padding =
  Property.property
    Gen.(
      let* n = gen_sint in
      let bytes = encode_s64 (Int64.of_int n) in
      let+ pad = gen_pad bytes in
      fun () ->
        let fill, last = if n < 0 then (0xff, 0x7f) else (0x80, 0x00) in
        let bytes = padded bytes ~fill ~last pad in
        check_decode Read.sleb128 bytes (Decoded (n, List.length bytes)))

(* On arbitrary bytes a read either rejects the input or consumes everything up
   to and including the first byte without a continuation bit. *)
let gen_bytes =
  Gen.(
    list (Range.linear 0 16)
      (frequency
         [
           (3, element [ 0x00; 0x7f; 0x80; 0xff ]);
           (1, int (Range.constant 0 255));
         ]))

let consumed bytes =
  let rec go i = function
    | [] -> None
    | b :: rest -> if b < 0x80 then Some (i + 1) else go (i + 1) rest
  in
  go 0 bytes

let arbitrary_bytes name read ~valid =
  Property.property
    Gen.(
      let+ bytes = gen_bytes in
      fun () ->
        Property.annotate (show_bytes bytes);
        match decode read bytes with
        | Rejected -> Property.classify "rejected" true
        | Decoded (v, n) ->
            Property.annotate (name ^ " = " ^ string_of_int v);
            Property.assert_ (Some n = consumed bytes && valid v))

let () =
  let tests = Property.with_tests 1000 in
  let ok =
    Property.check_group
      {
        name = "LEB128";
        properties =
          [
            ("uleb128 matches a 64-bit model", tests uleb128_model);
            ("sleb128 matches a 64-bit model", tests sleb128_model);
            ("uleb128 accepts padding", tests uleb128_padding);
            ("sleb128 accepts sign-extended padding", tests sleb128_padding);
            ( "uleb128 on arbitrary bytes",
              tests
                (arbitrary_bytes "uleb128" Read.uleb128 ~valid:(fun v -> v >= 0))
            );
            ( "sleb128 on arbitrary bytes",
              tests
                (arbitrary_bytes "sleb128" Read.sleb128 ~valid:(fun _ -> true))
            );
          ];
      }
  in
  if not ok then exit 1
