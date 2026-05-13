(** Tests for PE .pdata (runtime function table) read/write. *)

module Buffer = Stdlib.Buffer

let buffer_of_string s =
  let len = String.length s in
  let buf =
    Bigarray.Array1.create Bigarray.int8_unsigned Bigarray.c_layout len
  in
  for i = 0 to len - 1 do
    buf.{i} <- Char.code s.[i]
  done;
  buf

let u32 n = Unsigned.UInt32.of_int n

let test_pdata_roundtrip () =
  let entries =
    [
      Object.Pe.
        {
          begin_address = u32 0x1000;
          end_address = u32 0x1050;
          unwind_info_address = u32 0x3000;
        };
      {
        begin_address = u32 0x2000;
        end_address = u32 0x2100;
        unwind_info_address = u32 0x3020;
      };
    ]
  in
  let buf = Buffer.create 24 in
  Object.Pe.write_pdata buf entries;
  let bytes = Buffer.contents buf in
  Alcotest.(check int) "pdata size" 24 (String.length bytes);
  let obj_buf = buffer_of_string bytes in
  let sh : Object.Pe.section_header =
    {
      name = ".pdata";
      virtual_size = u32 24;
      virtual_address = u32 0;
      size_of_raw_data = u32 24;
      pointer_to_raw_data = u32 0;
      pointer_to_relocations = u32 0;
      pointer_to_line_numbers = u32 0;
      number_of_relocations = Unsigned.UInt16.zero;
      number_of_line_numbers = Unsigned.UInt16.zero;
      characteristics = [];
    }
  in
  let parsed = Object.Pe.parse_pdata obj_buf sh in
  Alcotest.(check int) "2 entries" 2 (Array.length parsed);
  Alcotest.(check int) "entry 0 begin" 0x1000
    (Unsigned.UInt32.to_int parsed.(0).begin_address);
  Alcotest.(check int) "entry 0 end" 0x1050
    (Unsigned.UInt32.to_int parsed.(0).end_address);
  Alcotest.(check int) "entry 0 unwind" 0x3000
    (Unsigned.UInt32.to_int parsed.(0).unwind_info_address);
  Alcotest.(check int) "entry 1 begin" 0x2000
    (Unsigned.UInt32.to_int parsed.(1).begin_address)

let () =
  Alcotest.run "PE Pdata"
    [
      ( "pdata",
        [ Alcotest.test_case "roundtrip" `Quick test_pdata_roundtrip ] );
    ]
