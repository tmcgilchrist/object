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

(* Pad a name to a fixed-width NUL-padded field. *)
let pad8 s = s ^ String.make (8 - String.length s) '\000'
let pad18 s = s ^ String.make (18 - String.length s) '\000'

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

(* Shared between [build_pe] and the entry-point assertion, so the value written
   and the value checked cannot drift. *)
let image_base = 0x140000000
let entry_rva = 0x1000

(* COFF machine codes written into the headers built below. *)
let machine_amd64 = 0x8664
let machine_arm64 = 0xaa64
let machine_riscv64 = 0x5064
let machine_arm64ec = 0xa641

(* The 112-byte fixed part of a PE32+ optional header, up to and including
   number_of_rva_and_sizes; the data directory follows. *)
let write_pe32plus_optional_header b ~num_rva =
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
  w32 b num_rva

(* Build a minimal PE32+ image. With [truncate_after_fixed] the buffer ends
   right after [number_of_rva_and_sizes], i.e. before the data directory. *)
let build_pe ?(machine = machine_amd64) ?(num_sections = 2) ?(num_rva = 16)
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
  write_pe32plus_optional_header b ~num_rva;
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

(* Machine type to architecture mapping, including the newer machine types. *)
let test_machine_to_arch () =
  let check label expected m =
    Alcotest.(check bool) label true (Pe.machine_to_arch m = expected)
  in
  check "i386" `X86 IMAGE_FILE_MACHINE_I386;
  check "amd64" `X86_64 IMAGE_FILE_MACHINE_AMD64;
  check "arm" `ARM IMAGE_FILE_MACHINE_ARM;
  check "arm64" `ARM64 IMAGE_FILE_MACHINE_ARM64;
  check "arm64ec" `ARM64 IMAGE_FILE_MACHINE_ARM64EC;
  check "arm64x" `ARM64 IMAGE_FILE_MACHINE_ARM64X;
  check "ia64" (`Unknown 0x200) IMAGE_FILE_MACHINE_IA64;
  check "riscv32" (`Unknown 0x5032) IMAGE_FILE_MACHINE_RISCV32;
  check "riscv64" (`Unknown 0x5064) IMAGE_FILE_MACHINE_RISCV64

(* The newer machine codes are recognised by [read], not left UNKNOWN. *)
let test_read_new_machine () =
  let machine_of code =
    (Pe.read (build_pe ~machine:code ())).Pe.coff_header.Pe.machine
  in
  Alcotest.(check bool)
    "riscv64" true
    (machine_of machine_riscv64 = Pe.IMAGE_FILE_MACHINE_RISCV64);
  Alcotest.(check bool)
    "arm64ec" true
    (machine_of machine_arm64ec = Pe.IMAGE_FILE_MACHINE_ARM64EC)

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

(* --- Exports --- *)

(* A PE32+ image with one .edata section (virtual address 0x1000, raw data at
   file offset 0x200) holding an export directory for "foo" (ordinal 1), "bar"
   (ordinal 2) and an ordinal-only export (ordinal 3). RVA X maps to file offset
   0x200 + (X - 0x1000). *)
let build_pe_with_exports () =
  let b = B.create 1024 in
  B.add_string b "MZ";
  pad_to b 60;
  w32 b 128;
  pad_to b 128;
  B.add_string b "PE\000\000";
  (* COFF header: one section, optional header present *)
  w16 b machine_amd64;
  w16 b 1;
  w32 b 0;
  w32 b 0;
  w32 b 0;
  w16 b 240;
  w16 b 0x2002 (* DLL | EXECUTABLE_IMAGE *);
  write_pe32plus_optional_header b ~num_rva:16;
  (* data directory: entry 0 = export table, rest zero *)
  w32 b 0x1000 (* export RVA *);
  w32 b 81 (* export size *);
  for _ = 2 to 16 do
    w32 b 0;
    w32 b 0
  done;
  (* section header: .edata *)
  B.add_string b (pad8 ".edata");
  w32 b 0x100 (* virtual_size *);
  w32 b 0x1000 (* virtual_address *);
  w32 b 0x100 (* size_of_raw_data *);
  w32 b 0x200 (* pointer_to_raw_data *);
  w32 b 0;
  w32 b 0;
  w16 b 0;
  w16 b 0;
  w32 b 0x40000040 (* INITIALIZED_DATA | READ *);
  (* export data at file offset 0x200 (RVA 0x1000) *)
  pad_to b 0x200;
  (* IMAGE_EXPORT_DIRECTORY *)
  w32 b 0 (* export flags *);
  w32 b 0 (* time/date stamp *);
  w16 b 0 (* major *);
  w16 b 0 (* minor *);
  w32 b 0x1048 (* DLL name RVA *);
  w32 b 1 (* ordinal base *);
  w32 b 3 (* number of address-table entries *);
  w32 b 2 (* number of name pointers *);
  w32 b 0x1028 (* export address table RVA *);
  w32 b 0x1034 (* name pointer table RVA *);
  w32 b 0x103c (* ordinal table RVA *);
  (* export address table *)
  w32 b 0x2000;
  w32 b 0x2010;
  w32 b 0x2020;
  (* name pointer table *)
  w32 b 0x1040;
  w32 b 0x1044;
  (* ordinal table *)
  w16 b 0;
  w16 b 1;
  (* name strings *)
  B.add_string b "foo\000";
  B.add_string b "bar\000";
  B.add_string b "test.dll\000";
  buffer_of_string (B.contents b)

let test_pe_exports () =
  let buf = build_pe_with_exports () in
  match Pe.read_exports buf (Pe.read buf) with
  | None -> Alcotest.fail "expected an export directory"
  | Some dir ->
      Alcotest.(check string) "dll name" "test.dll" dir.Pe.dll_name;
      Alcotest.(check int) "ordinal base" 1 dir.Pe.ordinal_base;
      let exports = dir.Pe.exports in
      Alcotest.(check int) "export count" 3 (Array.length exports);
      let name i = exports.(i).Pe.export_name in
      Alcotest.(check (option string)) "export 0 name" (Some "foo") (name 0);
      Alcotest.(check (option string)) "export 1 name" (Some "bar") (name 1);
      Alcotest.(check (option string)) "export 2 name" None (name 2);
      Alcotest.(check int) "export 0 ordinal" 1 exports.(0).Pe.export_ordinal;
      Alcotest.(check int) "export 2 ordinal" 3 exports.(2).Pe.export_ordinal;
      Alcotest.(check int)
        "export 0 address" 0x2000
        (Unsigned.UInt32.to_int exports.(0).Pe.export_address_rva)

let test_pe_no_exports () =
  let buf = build_pe () in
  Alcotest.(check bool) "none" true (Pe.read_exports buf (Pe.read buf) = None)

(* A bogus address-table count (file-controlled) must fail cleanly rather than
   over-allocate or read past the buffer. The count sits at offset 0x14 in the
   export directory, which the fixture places at file offset 0x200. *)
let test_pe_exports_bad_count () =
  let buf = build_pe_with_exports () in
  for i = 0 to 3 do
    buf.{0x214 + i} <- 0xff
  done;
  let pe = Pe.read buf in
  let raised =
    try
      ignore (Pe.read_exports buf pe);
      false
    with Object.Buffer.Invalid_format _ -> true
  in
  Alcotest.(check bool) "huge count raises Invalid_format" true raised

(* ------------------------------------------------------------------------- *)
(* COFF object files                                                         *)
(* ------------------------------------------------------------------------- *)

(* The 20-byte COFF header of a single-section object file (no optional
   header). *)
let write_coff_object_header b ?(machine = machine_amd64) ?(symtab = 0)
    ?(nsyms = 0) () =
  w16 b machine;
  w16 b 1 (* number_of_sections *);
  w32 b 0 (* time_date_stamp *);
  w32 b symtab (* pointer_to_symbol_table *);
  w32 b nsyms (* number_of_symbols *);
  w16 b 0 (* size_of_optional_header *);
  w16 b 0 (* characteristics *)

(* A 40-byte section header; the fixtures only vary the name and the relocation
   pointer/count. *)
let write_section_header b ~name ?(pointer_to_relocations = 0)
    ?(number_of_relocations = 0) () =
  B.add_string b (pad8 name);
  w32 b 0 (* virtual_size *);
  w32 b 0 (* virtual_address *);
  w32 b 0 (* size_of_raw_data *);
  w32 b 0 (* pointer_to_raw_data *);
  w32 b pointer_to_relocations;
  w32 b 0 (* pointer_to_line_numbers *);
  w16 b number_of_relocations;
  w16 b 0 (* number_of_line_numbers *);
  w32 b 0x60000020 (* CODE | EXECUTE | READ *)

(* A bare COFF object: a COFF header (no DOS/PE header, no optional header), one
   section whose name "/4" refers into the string table, and a string table
   holding the full name ".debug_info". With no symbols the string table sits
   directly after the section header, at file offset 60. *)
let build_coff ?(machine = machine_amd64) () =
  let b = B.create 128 in
  write_coff_object_header b ~machine ~symtab:60 ();
  write_section_header b ~name:"/4" ();
  (* String table: 4-byte size (counting itself) then ".debug_info\0". *)
  let s = ".debug_info\000" in
  w32 b (4 + String.length s);
  B.add_string b s;
  buffer_of_string (B.contents b)

(* --- Format detection --- *)

let test_coff_detection () =
  let coff = build_coff () in
  Alcotest.(check bool) "is_coff" true (Pe.is_coff coff);
  Alcotest.(check bool) "not is_pe" false (Pe.is_pe coff);
  let pe = build_pe () in
  Alcotest.(check bool) "image not is_coff" false (Pe.is_coff pe);
  Alcotest.(check bool) "image is_pe" true (Pe.is_pe pe)

(* --- Header parsing --- *)

(* A COFF object has no optional header and parses from offset 0. *)
let test_coff_headers () =
  let coff = Pe.read (build_coff ()) in
  Alcotest.(check bool)
    "no optional header" true
    (coff.Pe.optional_header = None);
  Alcotest.(check string)
    "machine" "amd64"
    (Pe.machine_type_to_string coff.Pe.coff_header.Pe.machine);
  Alcotest.(check int) "num sections" 1 (Array.length coff.Pe.section_headers)

(* --- Section handling --- *)

(* A "/N" section name is resolved against the string table. *)
let test_coff_long_section_name () =
  let coff = Pe.read (build_coff ()) in
  Alcotest.(check string)
    "long name" ".debug_info" coff.Pe.section_headers.(0).Pe.name

let test_coff_string_table () =
  let coff = Pe.read (build_coff ()) in
  match coff.Pe.string_table with
  | Some tbl ->
      Alcotest.(check string)
        "lookup offset 4" ".debug_info"
        (Pe.string_table_get tbl 4)
  | None -> Alcotest.fail "expected a string table"

(* --- Symbol table --- *)

(* A COFF object whose symbol table exercises: a .file symbol with a filename
   aux record, an external function with a function-definition aux record, a
   long name resolved via the string table, and an undefined symbol. The symbol
   table sits at offset 60 (header 20 + one 40-byte section header); six 18-byte
   records put the string table at offset 168. *)
let build_coff_with_symbols () =
  let b = B.create 256 in
  (* 6 symbol records, two of which are aux records. *)
  write_coff_object_header b ~symtab:60 ~nsyms:6 ();
  write_section_header b ~name:".text" ();
  (* symbol records *)
  let sym name ~value ~section ~typ ~storage ~aux =
    B.add_string b name;
    w32 b value;
    w16 b (section land 0xffff);
    w16 b typ;
    w8 b storage;
    w8 b aux
  in
  (* .file (storage class 103) carrying the source file name. *)
  sym (pad8 ".file") ~value:0 ~section:(-2) ~typ:0 ~storage:103 ~aux:1;
  B.add_string b (pad18 "main.c");
  (* main: an external function in section 1 with a function-definition aux. *)
  sym (pad8 "main") ~value:0 ~section:1 ~typ:0x20 ~storage:2 ~aux:1;
  w32 b 0 (* tag index *);
  w32 b 0x40 (* total size *);
  w32 b 0 (* pointer to line number *);
  w32 b 0 (* pointer to next function *);
  w16 b 0 (* unused *);
  (* a >8 char name stored in the string table at offset 4 *)
  sym "\000\000\000\000\004\000\000\000" ~value:0x10 ~section:1 ~typ:0
    ~storage:2 ~aux:0;
  (* undefined symbol: section number 0 *)
  sym (pad8 "undef") ~value:0 ~section:0 ~typ:0 ~storage:2 ~aux:0;
  (* string table: size prefix then the long name *)
  let s = "verylongsymbol\000" in
  w32 b (4 + String.length s);
  B.add_string b s;
  buffer_of_string (B.contents b)

(* Primary symbols are returned (aux skipped) with names, sections, storage
   classes and types decoded. *)
let test_coff_symbols () =
  let buf = build_coff_with_symbols () in
  let coff = Pe.read buf in
  let syms = Pe.read_symbols buf coff in
  Alcotest.(check int) "primary count (aux skipped)" 4 (Array.length syms);
  let names = Array.to_list (Array.map (fun s -> s.Pe.sym_name) syms) in
  Alcotest.(check (list string))
    "names"
    [ ".file"; "main"; "verylongsymbol"; "undef" ]
    names;
  Alcotest.(check int) ".file section" (-2) syms.(0).Pe.sym_section_number;
  Alcotest.(check int) "main section" 1 syms.(1).Pe.sym_section_number;
  Alcotest.(check bool)
    "main external" true
    (syms.(1).Pe.sym_storage_class = Pe.IMAGE_SYM_CLASS_EXTERNAL);
  Alcotest.(check bool)
    "main is a function" true
    (syms.(1).Pe.sym_type.Pe.complex_type = Pe.IMAGE_SYM_DTYPE_FUNCTION);
  Alcotest.(check int)
    "long-name value" 0x10
    (Unsigned.UInt32.to_int syms.(2).Pe.sym_value);
  Alcotest.(check int) "undef section" 0 syms.(3).Pe.sym_section_number

(* Auxiliary records are decoded according to the primary symbol's class. *)
let test_coff_aux_records () =
  let buf = build_coff_with_symbols () in
  let syms = Pe.read_symbols buf (Pe.read buf) in
  (match syms.(0).Pe.sym_aux with
  | [ Pe.Aux_file name ] -> Alcotest.(check string) "file name" "main.c" name
  | _ -> Alcotest.fail "expected an Aux_file record");
  match syms.(1).Pe.sym_aux with
  | [ Pe.Aux_function_definition { total_size; _ } ] ->
      Alcotest.(check int)
        "function size" 0x40
        (Unsigned.UInt32.to_int total_size)
  | _ -> Alcotest.fail "expected an Aux_function_definition record"

(* No symbol table: an empty table (count 0) and a stripped image (pointer 0). *)
let test_no_symbols () =
  let cbuf = build_coff () in
  Alcotest.(check int)
    "coff: none" 0
    (Array.length (Pe.read_symbols cbuf (Pe.read cbuf)));
  let pbuf = build_pe () in
  Alcotest.(check int)
    "image: none" 0
    (Array.length (Pe.read_symbols pbuf (Pe.read pbuf)))

(* --- Relocations --- *)

(* A COFF object with a single section whose relocation table holds [relocs]
   (each a virtual-address, symbol-index, type triple). The section header sits
   at offset 20 and the relocation table directly after it, at offset 60. *)
let build_coff_with_relocations ?(machine = machine_amd64) relocs =
  let b = B.create 128 in
  write_coff_object_header b ~machine ();
  write_section_header b ~name:".text" ~pointer_to_relocations:60
    ~number_of_relocations:(List.length relocs) ();
  (* relocation table: 10 bytes each *)
  List.iter
    (fun (va, sym, typ) ->
      w32 b va;
      w32 b sym;
      w16 b typ)
    relocs;
  buffer_of_string (B.contents b)

let test_coff_relocations () =
  let buf = build_coff_with_relocations [ (0x10, 5, 0x4); (0x20, 6, 0x1) ] in
  let coff = Pe.read buf in
  let relocs = Pe.read_relocations buf coff coff.Pe.section_headers.(0) in
  Alcotest.(check int) "count" 2 (Array.length relocs);
  Alcotest.(check int)
    "reloc 0 va" 0x10
    (Unsigned.UInt32.to_int relocs.(0).Pe.reloc_virtual_address);
  Alcotest.(check int)
    "reloc 0 symbol" 5
    (Unsigned.UInt32.to_int relocs.(0).Pe.reloc_symbol_table_index);
  Alcotest.(check bool)
    "reloc 0 type" true
    (relocs.(0).Pe.reloc_type = Pe.Reloc_amd64 Pe.IMAGE_REL_AMD64_REL32);
  Alcotest.(check bool)
    "reloc 1 type" true
    (relocs.(1).Pe.reloc_type = Pe.Reloc_amd64 Pe.IMAGE_REL_AMD64_ADDR64)

(* The relocation type is decoded for the file's machine. *)
let test_coff_relocations_arm64 () =
  let buf =
    build_coff_with_relocations ~machine:machine_arm64 [ (0x0, 1, 0x3) ]
  in
  let coff = Pe.read buf in
  let relocs = Pe.read_relocations buf coff coff.Pe.section_headers.(0) in
  Alcotest.(check bool)
    "arm64 branch26" true
    (relocs.(0).Pe.reloc_type = Pe.Reloc_arm64 Pe.IMAGE_REL_ARM64_BRANCH26)

let test_coff_no_relocations () =
  let buf = build_coff () in
  let coff = Pe.read buf in
  Alcotest.(check int)
    "none" 0
    (Array.length (Pe.read_relocations buf coff coff.Pe.section_headers.(0)))

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
      ( "PE: exports",
        [
          Alcotest.test_case "export table" `Quick test_pe_exports;
          Alcotest.test_case "no exports" `Quick test_pe_no_exports;
          Alcotest.test_case "malformed count" `Quick test_pe_exports_bad_count;
        ] );
      ( "COFF: headers",
        [
          Alcotest.test_case "format detection" `Quick test_coff_detection;
          Alcotest.test_case "read headers" `Quick test_coff_headers;
        ] );
      ( "COFF: sections",
        [
          Alcotest.test_case "long section name" `Quick
            test_coff_long_section_name;
          Alcotest.test_case "string table lookup" `Quick test_coff_string_table;
        ] );
      ( "COFF: symbols",
        [
          Alcotest.test_case "symbol table" `Quick test_coff_symbols;
          Alcotest.test_case "auxiliary records" `Quick test_coff_aux_records;
          Alcotest.test_case "no symbol table" `Quick test_no_symbols;
        ] );
      ( "COFF: relocations",
        [
          Alcotest.test_case "relocation table" `Quick test_coff_relocations;
          Alcotest.test_case "machine-specific type" `Quick
            test_coff_relocations_arm64;
          Alcotest.test_case "no relocations" `Quick test_coff_no_relocations;
        ] );
    ]
