open Object.Buffer

(* Helper function to create a buffer from bytes *)
let buffer_from_bytes bytes =
  let len = List.length bytes in
  let buffer =
    Bigarray.Array1.create Bigarray.int8_unsigned Bigarray.c_layout len
  in
  List.iteri (fun i byte -> buffer.{i} <- byte) bytes;
  buffer

let test_uleb128_single_byte () =
  (* Test values that fit in a single byte (0-127) *)
  let test_cases =
    [
      ([ 0x00 ], 0);
      (* 0 *)
      ([ 0x01 ], 1);
      (* 1 *)
      ([ 0x7F ], 127);
      (* 127, maximum single byte *)
    ]
  in

  List.iter
    (fun (bytes, expected) ->
      let buffer = buffer_from_bytes bytes in
      let cursor = cursor buffer in
      let result = Read.uleb128 cursor in
      Alcotest.(check int)
        (Printf.sprintf "uleb128 single byte %d" expected)
        expected result)
    test_cases

let test_uleb128_multi_byte () =
  (* Test values that require multiple bytes *)
  let test_cases =
    [
      ([ 0x80; 0x01 ], 128);
      (* 128 = 0x80, 0x01 *)
      ([ 0x81; 0x01 ], 129);
      (* 129 = 0x81, 0x01 *)
      ([ 0xFF; 0x01 ], 255);
      (* 255 = 0xFF, 0x01 *)
      ([ 0x80; 0x02 ], 256);
      (* 256 = 0x80, 0x02 *)
      ([ 0x81; 0x02 ], 257);
      (* 257 = 0x81, 0x02 *)
      ([ 0xE5; 0x8E; 0x26 ], 624485);
      (* 624485 = 0xE5, 0x8E, 0x26 *)
    ]
  in

  List.iter
    (fun (bytes, expected) ->
      let buffer = buffer_from_bytes bytes in
      let cursor = cursor buffer in
      let result = Read.uleb128 cursor in
      Alcotest.(check int)
        (Printf.sprintf "uleb128 multi byte %d" expected)
        expected result)
    test_cases

let test_uleb128_edge_cases () =
  (* Test edge cases and larger values *)
  let test_cases =
    [
      ([ 0x80; 0x80; 0x01 ], 16384);
      (* 16384 = 0x80, 0x80, 0x01 *)
      ([ 0xFF; 0xFF; 0x7F ], 2097151);
      (* 2097151 = 0xFF, 0xFF, 0x7F *)
    ]
  in

  List.iter
    (fun (bytes, expected) ->
      let buffer = buffer_from_bytes bytes in
      let cursor = cursor buffer in
      let result = Read.uleb128 cursor in
      Alcotest.(check int)
        (Printf.sprintf "uleb128 edge case %d" expected)
        expected result)
    test_cases

let test_sleb128_positive () =
  (* Test positive values in SLEB128 *)
  let test_cases =
    [
      ([ 0x00 ], 0);
      (* 0 *)
      ([ 0x01 ], 1);
      (* 1 *)
      ([ 0x3E ], 62);
      (* 62 - positive, no sign bit set *)
      ([ 0x80; 0x01 ], 128);
      (* 128 = 0x80, 0x01 *)
      ([ 0x81; 0x01 ], 129);
      (* 129 = 0x81, 0x01 *)
    ]
  in

  List.iter
    (fun (bytes, expected) ->
      let buffer = buffer_from_bytes bytes in
      let cursor = cursor buffer in
      let result = Read.sleb128 cursor in
      Alcotest.(check int)
        (Printf.sprintf "sleb128 positive %d" expected)
        expected result)
    test_cases

let test_sleb128_negative () =
  (* Test negative values in SLEB128 *)
  let test_cases =
    [
      ([ 0x7F ], -1);
      (* -1 = 0x7F *)
      ([ 0x7E ], -2);
      (* -2 = 0x7E *)
      ([ 0x40 ], -64);
      (* -64 = 0x40 (sign bit set, extend with 1s) *)
      ([ 0xFF; 0x7E ], -129);
      (* -129 = 0xFF, 0x7E *)
      ([ 0x80; 0x7F ], -128);
      (* -128 = 0x80, 0x7F *)
    ]
  in

  List.iter
    (fun (bytes, expected) ->
      let buffer = buffer_from_bytes bytes in
      let cursor = cursor buffer in
      let result = Read.sleb128 cursor in
      Alcotest.(check int)
        (Printf.sprintf "sleb128 negative %d" expected)
        expected result)
    test_cases

let test_sleb128_edge_cases () =
  (* Test SLEB128 edge cases *)
  let test_cases =
    [
      ([ 0x80; 0x80; 0x01 ], 16384);
      (* Large positive: 16384 *)
      ([ 0x80; 0x80; 0x7F ], -16384);
      (* Large negative: -16384 *)
    ]
  in

  List.iter
    (fun (bytes, expected) ->
      let buffer = buffer_from_bytes bytes in
      let cursor = cursor buffer in
      let result = Read.sleb128 cursor in
      Alcotest.(check int)
        (Printf.sprintf "sleb128 edge case %d" expected)
        expected result)
    test_cases

let raises_invalid_format name f =
  match f () with
  | exception Invalid_format _ -> ()
  | _ -> Alcotest.failf "%s: expected Invalid_format" name

let repeat n x = List.init n (fun _ -> x)

(* Nine 7-bit groups fill an OCaml int, a tenth byte may only pad (0x00), or
   sign-extend (0x7f) for sleb128. Anything wider is rejected. *)
let test_leb128_limits () =
  let uleb bytes = Read.uleb128 (cursor (buffer_from_bytes bytes)) in
  let sleb bytes = Read.sleb128 (cursor (buffer_from_bytes bytes)) in
  Alcotest.(check int)
    "uleb128 max_int" max_int
    (uleb (repeat 8 0xff @ [ 0x3f ]));
  Alcotest.(check int) "uleb128 padding" 0 (uleb (repeat 9 0x80 @ [ 0x00 ]));
  Alcotest.(check int)
    "sleb128 -1 in ten bytes" (-1)
    (sleb (repeat 9 0xff @ [ 0x7f ]));
  Alcotest.(check int)
    "sleb128 min_int" min_int
    (sleb (repeat 8 0x80 @ [ 0x40 ]));
  raises_invalid_format "uleb128 bit 63" (fun () ->
      uleb (repeat 9 0xff @ [ 0x01 ]));
  raises_invalid_format "uleb128 too long" (fun () ->
      uleb (repeat 20 0x80 @ [ 0x01 ]));
  raises_invalid_format "sleb128 too large" (fun () ->
      sleb (repeat 9 0x80 @ [ 0x01 ]));
  raises_invalid_format "sleb128 bad sign extension" (fun () ->
      sleb (repeat 8 0x80 @ [ 0xc0; 0x00 ]))

let test_cursor_position_advance () =
  (* Test that cursor position advances correctly after reading *)
  let buffer = buffer_from_bytes [ 0x80; 0x01; 0x7F ] in
  let cursor = cursor buffer in

  (* Read first ULEB128 (128, takes 2 bytes) *)
  let _result1 = Read.uleb128 cursor in
  Alcotest.(check int) "cursor position after uleb128" 2 cursor.position;

  (* Read second SLEB128 (-1, takes 1 byte) *)
  let _result2 = Read.sleb128 cursor in
  Alcotest.(check int) "cursor position after sleb128" 3 cursor.position

let test_dwarf_examples () =
  (* Test some real-world DWARF examples *)
  let test_cases =
    [
      (* Common DWARF tag and attribute values *)
      ([ 0x11 ], 0x11, "DW_TAG_compile_unit");
      ([ 0x24 ], 0x24, "DW_TAG_base_type");
      ([ 0x2E ], 0x2E, "DW_TAG_subprogram");
      ([ 0x80; 0x01 ], 128, "large DWARF value");
    ]
  in

  List.iter
    (fun (bytes, expected, desc) ->
      let buffer = buffer_from_bytes bytes in
      let cursor = cursor buffer in
      let result = Read.uleb128 cursor in
      Alcotest.(check int)
        (Printf.sprintf "DWARF example: %s" desc)
        expected result)
    test_cases

let () =
  let open Alcotest in
  run "LEB128 Tests"
    [
      ( "uleb128",
        [
          test_case "single byte values" `Quick test_uleb128_single_byte;
          test_case "multi byte values" `Quick test_uleb128_multi_byte;
          test_case "edge cases" `Quick test_uleb128_edge_cases;
        ] );
      ( "sleb128",
        [
          test_case "positive values" `Quick test_sleb128_positive;
          test_case "negative values" `Quick test_sleb128_negative;
          test_case "edge cases" `Quick test_sleb128_edge_cases;
        ] );
      ( "general",
        [
          test_case "cursor position advance" `Quick
            test_cursor_position_advance;
          test_case "DWARF examples" `Quick test_dwarf_examples;
          test_case "limits" `Quick test_leb128_limits;
        ] );
    ]
