(** Tests for the PE/COFF reader. *)

module B = Stdlib.Buffer
module Pe = Object.Pe
module Of = Object.Object_format

(* Little-endian writers into a byte buffer. *)
let w8 b v = B.add_char b (Char.chr (v land 0xff))

let w16 b v =
  w8 b v;
  w8 b (v lsr 8)

let w32 b v =
  w16 b (v land 0xffff);
  w16 b ((v lsr 16) land 0xffff)

let w64 b v =
  w32 b (v land 0xffffffff);
  w32 b ((v lsr 32) land 0xffffffff)

let pad_to b n =
  while B.length b < n do
    B.add_char b '\000'
  done

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
let u64_to_int = Unsigned.UInt64.to_int

(* ------------------------------------------------------------------------- *)
(* PE (Portable Executable) images                                           *)
(* ------------------------------------------------------------------------- *)

(* Section tuple: name, virtual_size, virtual_address, size_of_raw_data,
   pointer_to_raw_data, characteristics. *)
let default_sections =
  [
    (".text", 0x100, 0x1000, 0x200, 0x200, 0x60000020);
    (* .bss: present in memory but with no bytes on disk. *)
    (".bss", 0x1000, 0x2000, 0x0, 0x0, 0xC0000080);
  ]

let image_base = 0x140000000
let entry_rva = 0x1000

(* Build a minimal PE32+ image. With [truncate_after_fixed] the buffer ends
   right after [number_of_rva_and_sizes], i.e. before the data directory. *)
let build_pe ?(machine = 0x8664) ?(num_sections = 2) ?(num_rva = 16)
    ?(sections = default_sections) ?(truncate_after_fixed = false) () =
  let b = B.create 1024 in
  (* DOS header: "MZ" then e_lfanew at offset 60 pointing to the PE header. *)
  B.add_string b "MZ";
  pad_to b 60;
  w32 b 128;
  pad_to b 128;
  B.add_string b "PE\000\000";
  (* COFF header *)
  w16 b machine;
  w16 b num_sections;
  w32 b 0;
  w32 b 0;
  w32 b 0;
  w16 b 240 (* size_of_optional_header *);
  w16 b 0x0002 (* IMAGE_FILE_EXECUTABLE_IMAGE *);
  (* Optional header (PE32+) fixed fields *)
  w16 b 0x20b;
  w8 b 14;
  w8 b 0;
  w32 b 0x200;
  w32 b 0;
  w32 b 0;
  w32 b entry_rva;
  w32 b 0x1000;
  w64 b image_base;
  w32 b 0x1000;
  w32 b 0x200;
  w16 b 6;
  w16 b 0;
  w16 b 0;
  w16 b 0;
  w16 b 6;
  w16 b 0;
  w32 b 0;
  w32 b 0x4000;
  w32 b 0x200;
  w32 b 0;
  w16 b 3;
  w16 b 0;
  w64 b 0x100000;
  w64 b 0x1000;
  w64 b 0x100000;
  w64 b 0x1000;
  w32 b 0;
  w32 b num_rva;
  if not truncate_after_fixed then begin
    for _ = 1 to num_rva do
      w32 b 0;
      w32 b 0
    done;
    List.iter
      (fun (name, vsize, vaddr, rawsize, rawptr, chars) ->
        let nm = name ^ String.make (max 0 (8 - String.length name)) '\000' in
        B.add_string b (String.sub nm 0 8);
        w32 b vsize;
        w32 b vaddr;
        w32 b rawsize;
        w32 b rawptr;
        w32 b 0;
        w32 b 0;
        w16 b 0;
        w16 b 0;
        w32 b chars)
      sections;
    (* .text raw data at file offset 0x200. *)
    pad_to b 0x200;
    for _ = 1 to 0x200 do
      w8 b 0xAB
    done
  end;
  buffer_of_string (B.contents b)

(* --- Header parsing --- *)

let test_read_headers () =
  let pe = Pe.read (build_pe ()) in
  Alcotest.(check bool) "is_64bit" true (Pe.is_64bit pe);
  Alcotest.(check bool) "is_executable" true (Pe.is_executable pe);
  Alcotest.(check string)
    "machine" "amd64"
    (Pe.machine_type_to_string pe.Pe.coff_header.Pe.machine);
  let shs = pe.Pe.section_headers in
  Alcotest.(check int) "num sections" 2 (Array.length shs);
  Alcotest.(check string) "section 0" ".text" shs.(0).Pe.name;
  Alcotest.(check string) "section 1" ".bss" shs.(1).Pe.name

(* The entry point is the virtual address image_base + RVA, not the bare RVA. *)
let test_entry_point () =
  let pe = Pe.read (build_pe ()) in
  match Pe.entry_point pe with
  | Some ep ->
      Alcotest.(check int)
        "entry = image_base + rva" (image_base + entry_rva) (u64_to_int ep)
  | None -> Alcotest.fail "expected an entry point"

(* A data directory that runs past the end of the buffer raises a clean
   Invalid_format rather than an out-of-bounds Invalid_argument. *)
let test_truncated_data_directory () =
  let buf = build_pe ~num_rva:16 ~truncate_after_fixed:true () in
  let raised =
    try
      ignore (Pe.read buf);
      false
    with Object.Buffer.Invalid_format _ -> true
  in
  Alcotest.(check bool) "raises Invalid_format" true raised

(* --- Section handling --- *)

(* section_contents uses the on-disk size; a .bss-style section with no raw
   data yields an empty slice rather than reading past the buffer. *)
let test_section_contents () =
  let buf = build_pe () in
  let t = Of.read buf in
  (match Of.find_section t ".bss" with
  | Some s ->
      let c = Of.section_contents buf t s in
      Alcotest.(check int) ".bss on-disk bytes" 0 (Bigarray.Array1.dim c)
  | None -> Alcotest.fail "missing .bss section");
  match Of.find_section t ".text" with
  | Some s ->
      let c = Of.section_contents buf t s in
      Alcotest.(check int) ".text on-disk bytes" 0x200 (Bigarray.Array1.dim c)
  | None -> Alcotest.fail "missing .text section"

(* The .pdata section holds an array of RUNTIME_FUNCTION records (the Windows
   x64/ARM64 exception/unwind table). *)

let entry begin_ end_ unwind =
  Pe.
    {
      begin_address = u32 begin_;
      end_address = u32 end_;
      unwind_info_address = u32 unwind;
    }

(* A .pdata section header describing [size] bytes at file offset [ptr]. *)
let pdata_section ?(ptr = 0) size =
  Pe.
    {
      name = ".pdata";
      virtual_size = u32 size;
      virtual_address = u32 0;
      size_of_raw_data = u32 size;
      pointer_to_raw_data = u32 ptr;
      pointer_to_relocations = u32 0;
      pointer_to_line_numbers = u32 0;
      number_of_relocations = Unsigned.UInt16.zero;
      number_of_line_numbers = Unsigned.UInt16.zero;
      characteristics = [];
    }

let check_entry label (e : Pe.runtime_function) ~begin_ ~end_ ~unwind =
  let i = Unsigned.UInt32.to_int in
  Alcotest.(check int) (label ^ " begin") begin_ (i e.begin_address);
  Alcotest.(check int) (label ^ " end") end_ (i e.end_address);
  Alcotest.(check int) (label ^ " unwind") unwind (i e.unwind_info_address)

(* Serialise [entries] then parse the bytes straight back. *)
let roundtrip entries =
  let buf = B.create 64 in
  Pe.write_pdata buf entries;
  let bytes = B.contents buf in
  let parsed =
    Pe.parse_pdata (buffer_of_string bytes)
      (pdata_section (String.length bytes))
  in
  (bytes, parsed)

let test_pdata_roundtrip () =
  let entries = [ entry 0x1000 0x1050 0x3000; entry 0x2000 0x2100 0x3020 ] in
  let bytes, parsed = roundtrip entries in
  Alcotest.(check int) "byte size" 24 (String.length bytes);
  Alcotest.(check int) "entry count" 2 (Array.length parsed);
  check_entry "entry 0" parsed.(0) ~begin_:0x1000 ~end_:0x1050 ~unwind:0x3000;
  check_entry "entry 1" parsed.(1) ~begin_:0x2000 ~end_:0x2100 ~unwind:0x3020

let test_pdata_empty () =
  let bytes, parsed = roundtrip [] in
  Alcotest.(check int) "no bytes" 0 (String.length bytes);
  Alcotest.(check int) "no entries" 0 (Array.length parsed)

(* A RUNTIME_FUNCTION is three little-endian u32s, in order. *)
let test_pdata_byte_layout () =
  let buf = B.create 12 in
  Pe.write_pdata buf [ entry 0x11223344 0x55667788 0x99AABBCC ];
  let expected = "\x44\x33\x22\x11\x88\x77\x66\x55\xCC\xBB\xAA\x99" in
  Alcotest.(check string) "little-endian layout" expected (B.contents buf)

(* parse_pdata must read from pointer_to_raw_data, not the buffer start. *)
let test_pdata_parse_at_offset () =
  let buf = B.create 12 in
  Pe.write_pdata buf [ entry 0xDEAD 0xBEEF 0xCAFE ];
  let payload = B.contents buf in
  let padded = String.make 8 '\000' ^ payload in
  let parsed =
    Pe.parse_pdata (buffer_of_string padded)
      (pdata_section ~ptr:8 (String.length payload))
  in
  Alcotest.(check int) "one entry" 1 (Array.length parsed);
  check_entry "entry 0" parsed.(0) ~begin_:0xDEAD ~end_:0xBEEF ~unwind:0xCAFE

(* A size that is not a whole number of 12-byte records: the partial tail is
   ignored (count = size / 12). *)
let test_pdata_trailing_bytes_ignored () =
  let buf = B.create 24 in
  Pe.write_pdata buf [ entry 1 2 3; entry 4 5 6 ];
  let bytes = B.contents buf ^ "\x07\x07\x07\x07\x07" in
  let parsed =
    Pe.parse_pdata (buffer_of_string bytes)
      (pdata_section (String.length bytes))
  in
  Alcotest.(check int) "two whole entries" 2 (Array.length parsed);
  check_entry "entry 1" parsed.(1) ~begin_:4 ~end_:5 ~unwind:6

(* ------------------------------------------------------------------------- *)
(* COFF object files                                                         *)
(* ------------------------------------------------------------------------- *)

(* Bare COFF object files (no DOS/PE header) are not yet read; their header
   and section tests will live here once they are supported. *)

let () =
  Alcotest.run "PE/COFF reader"
    [
      ( "PE: headers",
        [
          Alcotest.test_case "read headers" `Quick test_read_headers;
          Alcotest.test_case "entry point" `Quick test_entry_point;
          Alcotest.test_case "machine_to_arch" `Quick test_machine_to_arch;
          Alcotest.test_case "read new machine" `Quick test_read_new_machine;
          Alcotest.test_case "truncated data directory" `Quick
            test_truncated_data_directory;
        ] );
      ( "PE: sections",
        [
          Alcotest.test_case "section_contents" `Quick test_section_contents;
          Alcotest.test_case ".pdata roundtrip" `Quick test_pdata_roundtrip;
          Alcotest.test_case ".pdata empty" `Quick test_pdata_empty;
          Alcotest.test_case ".pdata byte layout" `Quick test_pdata_byte_layout;
          Alcotest.test_case ".pdata parse at offset" `Quick
            test_pdata_parse_at_offset;
          Alcotest.test_case ".pdata trailing bytes ignored" `Quick
            test_pdata_trailing_bytes_ignored;
        ] );
    ]
