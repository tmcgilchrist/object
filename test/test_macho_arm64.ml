open Object
open Object.Macho

let test_macho_header hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let header, _commands = Macho.read buffer in

  (* Test magic number (should be 64-bit ARM64) *)
  Alcotest.(check bool)
    "is 64-bit" true
    (match header.magic with MAGIC64 -> true | _ -> false);

  (* Test CPU type (should be ARM64) *)
  Alcotest.(check bool)
    "is ARM64" true
    (match header.cpu_type with `ARM64 -> true | _ -> false);

  (* Test file type (should be executable) *)
  Alcotest.(check bool)
    "is executable" true
    (match header.file_type with `EXECUTE -> true | _ -> false);

  (* Test flags include expected values *)
  let has_flag flag = List.mem flag header.flags in
  Alcotest.(check bool) "has NOUNDEFS flag" true (has_flag `NOUNDEFS);
  Alcotest.(check bool) "has DYLDLINK flag" true (has_flag `DYLDLINK);
  Alcotest.(check bool) "has TWOLEVEL flag" true (has_flag `TWOLEVEL);
  Alcotest.(check bool) "has PIE flag" true (has_flag `PIE)

let test_segments hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let _header, commands = Macho.read buffer in

  (* Extract all segments *)
  let segments =
    List.filter_map
      (function LC_SEGMENT_64 (lazy seg) -> Some seg | _ -> None)
      commands
  in

  (* Should have 4 segments: __PAGEZERO, __TEXT, __DATA_CONST, __LINKEDIT *)
  Alcotest.(check int) "number of segments" 4 (List.length segments);

  (* Check __TEXT segment *)
  let text_segment =
    List.find (fun seg -> seg.seg_segname = "__TEXT") segments
  in
  Alcotest.(check string)
    "__TEXT segment name" "__TEXT" text_segment.seg_segname;
  Alcotest.(check int)
    "__TEXT sections count" 4
    (Array.length text_segment.seg_sections);

  (* Check __DATA_CONST segment *)
  let data_segment =
    List.find (fun seg -> seg.seg_segname = "__DATA_CONST") segments
  in
  Alcotest.(check string)
    "__DATA_CONST segment name" "__DATA_CONST" data_segment.seg_segname;
  Alcotest.(check int)
    "__DATA_CONST sections count" 1
    (Array.length data_segment.seg_sections);

  (* Check __PAGEZERO segment *)
  let pagezero_segment =
    List.find (fun seg -> seg.seg_segname = "__PAGEZERO") segments
  in
  Alcotest.(check string)
    "__PAGEZERO segment name" "__PAGEZERO" pagezero_segment.seg_segname;
  Alcotest.(check int)
    "__PAGEZERO sections count" 0
    (Array.length pagezero_segment.seg_sections);

  (* Check __LINKEDIT segment *)
  let linkedit_segment =
    List.find (fun seg -> seg.seg_segname = "__LINKEDIT") segments
  in
  Alcotest.(check string)
    "__LINKEDIT segment name" "__LINKEDIT" linkedit_segment.seg_segname;
  Alcotest.(check int)
    "__LINKEDIT sections count" 0
    (Array.length linkedit_segment.seg_sections)

let test_text_sections hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let _header, commands = Macho.read buffer in

  (* Extract __TEXT segment *)
  let text_segment =
    match
      List.find_map
        (function
          | LC_SEGMENT_64 (lazy seg) when seg.seg_segname = "__TEXT" -> Some seg
          | _ -> None)
        commands
    with
    | Some seg -> seg
    | None -> Alcotest.fail "No __TEXT segment found"
  in

  let sections = Array.to_list text_segment.seg_sections in
  let section_names = List.map (fun s -> s.sec_sectname) sections in

  (* Check expected sections in __TEXT *)
  Alcotest.(check bool)
    "has __text section" true
    (List.mem "__text" section_names);
  Alcotest.(check bool)
    "has __stubs section" true
    (List.mem "__stubs" section_names);
  Alcotest.(check bool)
    "has __cstring section" true
    (List.mem "__cstring" section_names);
  Alcotest.(check bool)
    "has __unwind_info section" true
    (List.mem "__unwind_info" section_names);

  (* Check __text section properties *)
  let text_section = List.find (fun s -> s.sec_sectname = "__text") sections in
  Alcotest.(check string)
    "__text segment name" "__TEXT" text_section.sec_segname;
  Alcotest.(check bool)
    "__text size > 0" true
    (Unsigned.UInt64.compare text_section.sec_size (Unsigned.UInt64.of_int 0)
    > 0);

  (* Check __stubs section properties *)
  let stubs_section =
    List.find (fun s -> s.sec_sectname = "__stubs") sections
  in
  Alcotest.(check string)
    "__stubs segment name" "__TEXT" stubs_section.sec_segname;
  Alcotest.(check bool)
    "__stubs size > 0" true
    (Unsigned.UInt64.compare stubs_section.sec_size (Unsigned.UInt64.of_int 0)
    > 0);

  (* Check __cstring section properties *)
  let cstring_section =
    List.find (fun s -> s.sec_sectname = "__cstring") sections
  in
  Alcotest.(check string)
    "__cstring segment name" "__TEXT" cstring_section.sec_segname;
  Alcotest.(check bool)
    "__cstring size > 0" true
    (Unsigned.UInt64.compare cstring_section.sec_size (Unsigned.UInt64.of_int 0)
    > 0)

let test_data_sections hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let _header, commands = Macho.read buffer in

  (* Extract __DATA_CONST segment *)
  let data_segment =
    match
      List.find_map
        (function
          | LC_SEGMENT_64 (lazy seg) when seg.seg_segname = "__DATA_CONST" ->
              Some seg
          | _ -> None)
        commands
    with
    | Some seg -> seg
    | None -> Alcotest.fail "No __DATA_CONST segment found"
  in

  let sections = Array.to_list data_segment.seg_sections in
  let section_names = List.map (fun s -> s.sec_sectname) sections in

  (* Check expected sections in __DATA_CONST *)
  Alcotest.(check bool)
    "has __got section" true
    (List.mem "__got" section_names);

  (* Check __got section properties *)
  let got_section = List.find (fun s -> s.sec_sectname = "__got") sections in
  Alcotest.(check string)
    "__got segment name" "__DATA_CONST" got_section.sec_segname;
  Alcotest.(check bool)
    "__got size > 0" true
    (Unsigned.UInt64.compare got_section.sec_size (Unsigned.UInt64.of_int 0) > 0)

let test_load_commands hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let _header, commands = Macho.read buffer in

  (* Should have 17 load commands based on objdump output *)
  Alcotest.(check int) "number of load commands" 17 (List.length commands);

  (* Check for expected load command types *)
  Alcotest.(check bool)
    "has LC_SEGMENT_64" true
    (List.exists (function LC_SEGMENT_64 _ -> true | _ -> false) commands);
  Alcotest.(check bool)
    "has LC_SYMTAB" true
    (List.exists (function LC_SYMTAB _ -> true | _ -> false) commands);
  Alcotest.(check bool)
    "has LC_DYSYMTAB" true
    (List.exists (function LC_DYSYMTAB _ -> true | _ -> false) commands);
  Alcotest.(check bool)
    "has LC_LOAD_DYLINKER" true
    (List.exists (function LC_LOAD_DYLINKER _ -> true | _ -> false) commands);
  Alcotest.(check bool)
    "has LC_UUID" true
    (List.exists (function LC_UUID _ -> true | _ -> false) commands);

  (* Check that we have some unhandled commands (modern load commands) *)
  Alcotest.(check bool)
    "has LC_UNHANDLED commands" true
    (List.exists (function LC_UNHANDLED _ -> true | _ -> false) commands)

let test_symbol_table hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let _header, commands = Macho.read buffer in

  (* Extract symbol table command *)
  let symtab_opt =
    List.find_map
      (function
        | LC_SYMTAB (lazy (symbols, _strings)) -> Some symbols | _ -> None)
      commands
  in

  match symtab_opt with
  | Some symbols ->
      (* Should have 3 symbols according to objdump *)
      Alcotest.(check int) "symbol table size" 3 (Array.length symbols);

      (* Check that we have some symbols *)
      Alcotest.(check bool) "has symbols" true (Array.length symbols > 0)
  | None -> Alcotest.fail "No symbol table found"

let test_section_body_reading hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let _header, commands = Macho.read buffer in

  (* Get __TEXT segment and __cstring section *)
  let text_segment =
    match
      List.find_map
        (function
          | LC_SEGMENT_64 (lazy seg) when seg.seg_segname = "__TEXT" -> Some seg
          | _ -> None)
        commands
    with
    | Some seg -> seg
    | None -> Alcotest.fail "No __TEXT segment found"
  in

  let cstring_section =
    let sections = Array.to_list text_segment.seg_sections in
    List.find (fun s -> s.sec_sectname = "__cstring") sections
  in

  (* Read the section body *)
  let section_data = Macho.section_body buffer cstring_section in

  (* Should be able to read some data *)
  Alcotest.(check bool)
    "section data size > 0" true
    (Bigarray.Array1.dim section_data > 0);

  (* The __cstring section should contain "Hello, World!\n" *)
  let size = Bigarray.Array1.dim section_data in
  Alcotest.(check bool)
    "section has reasonable size" true
    (size >= 14 && size <= 20)

let binary_path =
  let doc = "Path to the binary file to test" in
  Cmdliner.Arg.(
    required & opt (some file) None & info [ "binary"; "b" ] ~doc ~docv:"BINARY")

let () =
  Alcotest.run_with_args "Mach-O ARM64 Tests" binary_path
    [
      ("header", [ ("parse header correctly", `Quick, test_macho_header) ]);
      ("segments", [ ("parse segments correctly", `Quick, test_segments) ]);
      ( "sections",
        [
          ("parse __TEXT sections correctly", `Quick, test_text_sections);
          ("parse __DATA_CONST sections correctly", `Quick, test_data_sections);
          ("read section body", `Quick, test_section_body_reading);
        ] );
      ( "load_commands",
        [
          ("parse load commands correctly", `Quick, test_load_commands);
          ("parse symbol table", `Quick, test_symbol_table);
        ] );
    ]
