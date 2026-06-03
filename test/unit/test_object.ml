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
    ]
