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

let buffer_of_array =
  Bigarray.Array1.of_array Bigarray.int8_unsigned Bigarray.c_layout

let raises_invalid_format name f =
  Alcotest.match_raises name
    (function Invalid_format _ -> true | _ -> false)
    (fun () -> ignore (f ()))

(* Reading past the end raises Invalid_format rather than Invalid_argument. *)
let test_read_out_of_bounds () =
  let short = buffer_of_array [| 1; 2; 3 |] in
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
      Read.uleb128 (cursor (buffer_of_array [| 0x80; 0x80 |])))

(* A huge length is rejected before anything is allocated. *)
let test_fixed_string_huge_length () =
  raises_invalid_format "fixed_string" (fun () ->
      Read.fixed_string (cursor (buffer_of_array [| 0 |])) max_int)

let test_negative_position () =
  let c = cursor (buffer_of_array [| 1; 2; 3; 4 |]) in
  seek c (-1);
  raises_invalid_format "u32 at -1" (fun () -> Read.u32 c);
  raises_invalid_format "ensure negative length" (fun () ->
      ensure (cursor (buffer_of_array [| 1 |])) (-1) "negative")

let test_u32be () =
  let c = cursor (buffer_of_array [| 0x12; 0x34; 0x56; 0x78 |]) in
  Alcotest.(check int)
    "big-endian" 0x12345678
    (Unsigned.UInt32.to_int (Read.u32be c));
  Alcotest.(check int) "advances 4 bytes" 4 c.position

(* [maxlen] is clamped to the buffer, and a missing terminator leaves the cursor
   unchanged. *)
let test_zero_string_bounds () =
  let c = cursor (buffer_of_array [| 0x61; 0x62 |]) in
  Alcotest.(check (option string))
    "no terminator" None
    (Read.zero_string c ~maxlen:100 ());
  Alcotest.(check int) "cursor unchanged" 0 c.position;
  Alcotest.(check (option string))
    "negative maxlen" None
    (Read.zero_string c ~maxlen:(-5) ());
  Alcotest.(check (option string))
    "past the end" None
    (Read.zero_string (cursor ~at:10 (buffer_of_array [| 0 |])) ());
  Alcotest.(check (option string))
    "negative position" None
    (Read.zero_string (cursor ~at:(-4) (buffer_of_array [| 0x61; 0 |])) ())

let buffer_of_hex hex =
  buffer_of_array
    (Array.init
       (String.length hex / 2)
       (fun i -> int_of_string ("0x" ^ String.sub hex (i * 2) 2)))

(* A 64-bit Mach-O with one __TEXT segment whose __text section claims
   0xffffffff relocations. *)
let macho_nreloc_huge =
  String.concat ""
    [
      "cffaedfe0c000001000000000100000001000000980000000000000000000000";
      "19000000980000005f5f54455854000000000000000000000000000000000000";
      "0000000000000000000000000000000000000000000000000700000005000000";
      "01000000000000005f5f74657874000000000000000000005f5f544558540000";
      "0000000000000000000000000000000000000000000000000000000000000000";
      "00000000ffffffff00000000000000000000000000000000";
    ]

(* An ELF whose .symtab has sh_entsize 1 and sh_size 0x7fffffff. *)
let elf_symtab_entsize1 =
  String.concat ""
    [
      "7f454c4602010100000000000000000002003e00010000000000000000000000";
      "0000000000000000980000000000000000000000400038000000400004000300";
      "0000000000000000000000000000000000000000000000000100000012000100";
      "00100000000000000000000000000000006d61696e00002e73796d746162002e";
      "737472746162002e736873747274616200000000000000000000000000000000";
      "0000000000000000000000000000000000000000000000000000000000000000";
      "0000000000000000010000000000000000000000000000000100000002000000";
      "000000000000000000000000000000004000000000000000ffffff7f00000000";
      "0200000000000000010000000000000001000000000000000900000003000000";
      "0000000000000000000000000000000070000000000000000600000000000000";
      "0000000000000000010000000000000000000000000000001100000003000000";
      "0000000000000000000000000000000076000000000000001b00000000000000";
      "000000000000000001000000000000000000000000000000";
    ]

(* Corrupt counts are rejected before allocating, instead of filling memory. *)
let test_macho_nreloc () =
  let _header, commands = Object.Macho.read (buffer_of_hex macho_nreloc_huge) in
  raises_invalid_format "nreloc" (fun () ->
      List.iter
        (function
          | Object.Macho.LC_SEGMENT_64 seg -> ignore (Lazy.force seg) | _ -> ())
        commands)

let test_elf_symtab_count () =
  let buffer = buffer_of_hex elf_symtab_entsize1 in
  let header, sections = Object.Elf.read_elf buffer in
  raises_invalid_format "symbol count" (fun () ->
      Object.Elf.read_symbol_table buffer header sections)

(* The same ELF with sh_size 0x0aaaaaaaaaaaaaab, so the symbol count times 24
   overflows to 8. *)
let elf_symtab_overflow =
  let at = 248 * 2 in
  String.sub elf_symtab_entsize1 0 at
  ^ "abaaaaaaaaaaaa0a"
  ^ String.sub elf_symtab_entsize1 (at + 16)
      (String.length elf_symtab_entsize1 - at - 16)

let test_elf_symtab_overflow () =
  let buffer = buffer_of_hex elf_symtab_overflow in
  let header, sections = Object.Elf.read_elf buffer in
  raises_invalid_format "symbol count" (fun () ->
      Object.Elf.read_symbol_table buffer header sections)

(* FAT_MAGIC claiming 0xffffffff architectures, followed by one x86_64 arch.
   The first arch must be readable, since [Array.init] reads it before
   allocating, and the error must come from the count check. *)
let test_fat_arch_count () =
  let buffer =
    buffer_of_hex "cafebabeffffffff010000070000000300001000000010000000000c"
  in
  Alcotest.check_raises "nfat_arch"
    (Invalid_format "table extends past the end of the buffer") (fun () ->
      ignore (Object.Macho.read_fat buffer))

(* A 64-bit Mach-O header followed by an empty LC_SEGMENT_64 of [cmdsize]
   bytes. *)
let macho_segment_64 cmdsize =
  let u32 n =
    [ n land 0xff; (n lsr 8) land 0xff; (n lsr 16) land 0xff; n lsr 24 ]
  in
  let header =
    List.concat_map u32 [ 0xfeedfacf; 0x0100000c; 0; 1; 1; cmdsize; 0; 0 ]
  in
  let command = u32 0x19 @ u32 cmdsize @ List.init (cmdsize - 8) (fun _ -> 0) in
  buffer_of_array (Array.of_list (header @ command))

(* A segment_command_64 is 72 bytes. *)
let test_macho_cmdsize () =
  raises_invalid_format "cmdsize 16" (fun () ->
      Object.Macho.read (macho_segment_64 16));
  raises_invalid_format "cmdsize 71" (fun () ->
      Object.Macho.read (macho_segment_64 71));
  let _header, commands = Object.Macho.read (macho_segment_64 72) in
  Alcotest.(check int) "cmdsize 72" 1 (List.length commands)

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
      ( "allocation",
        [
          test_case "Mach-O nreloc" `Quick test_macho_nreloc;
          test_case "ELF symbol count" `Quick test_elf_symtab_count;
          test_case "ELF symbol count overflow" `Quick test_elf_symtab_overflow;
          test_case "fat arch count" `Quick test_fat_arch_count;
        ] );
      ("macho", [ test_case "cmdsize minimum" `Quick test_macho_cmdsize ]);
    ]
