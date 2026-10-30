open Object.Buffer

let test_unsigned_types () =
  Alcotest.(check bool)
    "u8 type exists" true
    (match Unsigned.UInt8.zero with _ -> true);
  Alcotest.(check bool)
    "u32 type exists" true
    (match Unsigned.UInt32.zero with _ -> true);
  Alcotest.(check bool)
    "u64 type exists" true
    (match Unsigned.UInt64.zero with _ -> true)

let test_unsigned_conversions () =
  let u8_val = Unsigned.UInt8.of_int 42 in
  let u32_val = Unsigned.UInt32.of_int 42 in
  let u64_val = Unsigned.UInt64.of_int 42 in

  Alcotest.(check int) "u8 conversion" 42 (Unsigned.UInt8.to_int u8_val);
  Alcotest.(check int) "u32 conversion" 42 (Unsigned.UInt32.to_int u32_val);
  Alcotest.(check int) "u64 conversion" 42 (Unsigned.UInt64.to_int u64_val)

let test_signed_types () =
  let s8_val = Signed.Int8.of_int (-42) in
  let s32_val = Signed.Int32.of_int (-42) in
  let s64_val = Signed.Int64.of_int (-42) in

  Alcotest.(check int) "s8 conversion" (-42) (Signed.Int8.to_int s8_val);
  Alcotest.(check int) "s32 conversion" (-42) (Signed.Int32.to_int s32_val);
  Alcotest.(check int) "s64 conversion" (-42) (Signed.Int64.to_int s64_val)

let buffer_of_list bytes =
  let b =
    Bigarray.Array1.create Bigarray.int8_unsigned Bigarray.c_layout
      (List.length bytes)
  in
  List.iteri (fun i x -> b.{i} <- x) bytes;
  b

let raises_invalid_format name f =
  match f () with
  | exception Invalid_format _ -> ()
  | _ -> Alcotest.failf "%s: expected Invalid_format" name

(* Reading past the end raises Invalid_format rather than Invalid_argument. *)
let test_read_out_of_bounds () =
  let short = buffer_of_list [ 1; 2; 3 ] in
  let at_end () = cursor ~at:3 short in
  raises_invalid_format "u8" (fun () -> Read.u8 (at_end ()));
  raises_invalid_format "s8" (fun () -> Read.s8 (at_end ()));
  raises_invalid_format "u16" (fun () -> Read.u16 (cursor ~at:2 short));
  raises_invalid_format "u32" (fun () -> Read.u32 (cursor short));
  raises_invalid_format "u32be" (fun () -> Read.u32be (cursor short));
  raises_invalid_format "u64" (fun () -> Read.u64 (cursor short));
  raises_invalid_format "fixed_string" (fun () ->
      Read.fixed_string (cursor short) 4);
  raises_invalid_format "buffer" (fun () -> Read.buffer (cursor short) 4);
  raises_invalid_format "uleb128" (fun () ->
      Read.uleb128 (cursor (buffer_of_list [ 0x80; 0x80 ])))

(* A huge length is rejected before anything is allocated. *)
let test_fixed_string_huge_length () =
  raises_invalid_format "fixed_string" (fun () ->
      Read.fixed_string (cursor (buffer_of_list [ 0 ])) max_int)

let test_negative_position () =
  let c = cursor (buffer_of_list [ 1; 2; 3; 4 ]) in
  seek c (-1);
  raises_invalid_format "u32 at -1" (fun () -> Read.u32 c);
  raises_invalid_format "ensure negative length" (fun () ->
      ensure (cursor (buffer_of_list [ 1 ])) (-1) "negative")

let test_u32be () =
  let c = cursor (buffer_of_list [ 0x12; 0x34; 0x56; 0x78 ]) in
  Alcotest.(check int)
    "big-endian" 0x12345678
    (Unsigned.UInt32.to_int (Read.u32be c));
  Alcotest.(check int) "advances 4 bytes" 4 c.position

(* [maxlen] is clamped to the buffer, and a missing terminator leaves the cursor
   unchanged. *)
let test_zero_string_bounds () =
  let c = cursor (buffer_of_list [ 0x61; 0x62 ]) in
  Alcotest.(check (option string))
    "no terminator" None
    (Read.zero_string c ~maxlen:100 ());
  Alcotest.(check int) "cursor unchanged" 0 c.position;
  Alcotest.(check (option string))
    "negative maxlen" None
    (Read.zero_string c ~maxlen:(-5) ());
  Alcotest.(check (option string))
    "past the end" None
    (Read.zero_string (cursor ~at:10 (buffer_of_list [ 0 ])) ())

let () =
  let open Alcotest in
  run "Object Library Tests"
    [
      ( "types",
        [
          test_case "unsigned types" `Quick test_unsigned_types;
          test_case "unsigned conversions" `Quick test_unsigned_conversions;
          test_case "signed types" `Quick test_signed_types;
        ] );
      ( "buffer",
        [
          test_case "reads out of bounds" `Quick test_read_out_of_bounds;
          test_case "fixed_string huge length" `Quick
            test_fixed_string_huge_length;
          test_case "negative position" `Quick test_negative_position;
          test_case "u32be" `Quick test_u32be;
          test_case "zero_string bounds" `Quick test_zero_string_bounds;
        ] );
    ]
