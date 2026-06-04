open Object
open Elf

let test_elf_header_parsing hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let header, _sections = Elf.read_elf buffer in

  (* Test ELF magic by reading first 4 bytes of buffer *)
  let cursor = Buffer.cursor buffer in
  let magic0 = Buffer.Read.u8 cursor in
  let magic1 = Buffer.Read.u8 cursor in
  let magic2 = Buffer.Read.u8 cursor in
  let magic3 = Buffer.Read.u8 cursor in

  Alcotest.(check int) "ELF magic byte 0" 0x7f (Unsigned.UInt8.to_int magic0);
  Alcotest.(check int)
    "ELF magic byte 1" (Char.code 'E')
    (Unsigned.UInt8.to_int magic1);
  Alcotest.(check int)
    "ELF magic byte 2" (Char.code 'L')
    (Unsigned.UInt8.to_int magic2);
  Alcotest.(check int)
    "ELF magic byte 3" (Char.code 'F')
    (Unsigned.UInt8.to_int magic3);

  (* Test 64-bit class *)
  Alcotest.(check bool)
    "ELF class (64-bit)" true
    (match header.e_ident.elf_class with `ELFCLASS64 -> true | _ -> false);

  (* Test little-endian *)
  Alcotest.(check bool)
    "ELF data encoding (little-endian)" true
    (match header.e_ident.elf_data with `ELFDATA2LSB -> true | _ -> false);

  (* Test file type (position-independent executable) *)
  Alcotest.(check bool)
    "ELF type (PIE)" true
    (match header.e_type with `ET_DYN -> true | _ -> false);

  (* Test machine type (AArch64) *)
  Alcotest.(check bool)
    "ELF machine (AArch64)" true
    (match header.e_machine with `EM_AARCH64 -> true | _ -> false);

  (* Test entry point *)
  Alcotest.(check int64)
    "Entry point" 0x640L
    (Unsigned.UInt64.to_int64 header.e_entry);

  (* Test section header count *)
  Alcotest.(check bool)
    "Has sections" true
    (Unsigned.UInt16.to_int header.e_shnum > 0)

let test_elf_sections hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let _header, sections = Elf.read_elf buffer in

  (* Test section count *)
  Alcotest.(check bool) "Has multiple sections" true (Array.length sections > 20);

  (* Find and test specific sections *)
  let find_section name =
    Array.find_opt (fun sec -> sec.sh_name_str = name) sections
  in

  (* Test .text section *)
  (match find_section ".text" with
  | Some text_sec ->
      Alcotest.(check int64)
        ".text section size" 0x138L
        (Unsigned.UInt64.to_int64 text_sec.sh_size);
      Alcotest.(check int64)
        ".text section address" 0x640L
        (Unsigned.UInt64.to_int64 text_sec.sh_addr);
      Alcotest.(check int)
        ".text section type (PROGBITS)" 1
        (Unsigned.UInt32.to_int text_sec.sh_type)
  | None -> Alcotest.fail "Could not find .text section");

  (* Test .data section *)
  (match find_section ".data" with
  | Some data_sec ->
      Alcotest.(check int64)
        ".data section size" 0x10L
        (Unsigned.UInt64.to_int64 data_sec.sh_size);
      Alcotest.(check int64)
        ".data section address" 0x20000L
        (Unsigned.UInt64.to_int64 data_sec.sh_addr)
  | None -> Alcotest.fail "Could not find .data section");

  (* Test .bss section *)
  (match find_section ".bss" with
  | Some bss_sec ->
      Alcotest.(check int64)
        ".bss section size" 0x8L
        (Unsigned.UInt64.to_int64 bss_sec.sh_size);
      Alcotest.(check int)
        ".bss section type (NOBITS)" 8
        (Unsigned.UInt32.to_int bss_sec.sh_type)
  | None -> Alcotest.fail "Could not find .bss section");

  (* Test .rodata section *)
  match find_section ".rodata" with
  | Some rodata_sec ->
      Alcotest.(check int64)
        ".rodata section size" 0x16L
        (Unsigned.UInt64.to_int64 rodata_sec.sh_size);
      Alcotest.(check int64)
        ".rodata section address" 0x790L
        (Unsigned.UInt64.to_int64 rodata_sec.sh_addr)
  | None -> Alcotest.fail "Could not find .rodata section"

let test_elf_program_headers hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let header, _sections = Elf.read_elf buffer in
  let programs = Elf.read_programs buffer header in

  (* Test program header count *)
  Alcotest.(check bool)
    "Has multiple program headers" true
    (Array.length programs >= 8);

  (* Find LOAD segments *)
  let load_segments =
    Array.fold_left
      (fun acc prog ->
        match prog.p_type with `PT_LOAD -> prog :: acc | _ -> acc)
      [] programs
    |> List.rev
  in

  Alcotest.(check int) "Has 2 LOAD segments" 2 (List.length load_segments);

  (* Test first LOAD segment (text/rodata) *)
  (match load_segments with
  | first_load :: _ ->
      Alcotest.(check int64)
        "First LOAD segment virtual address" 0x0L
        (Unsigned.UInt64.to_int64 first_load.p_vaddr);
      Alcotest.(check int64)
        "First LOAD segment file size" 0x89cL
        (Unsigned.UInt64.to_int64 first_load.p_filesz);
      Alcotest.(check bool)
        "First LOAD segment is readable and executable" true
        (match first_load.p_flags with
        | `PF_RX | `PF_R | `PF_X -> true
        | `PF_W | `PF_RW | `PF_WX | `PF_RWX | `PF_MASKOS | `PF_MASKPROC -> false)
  | [] -> Alcotest.fail "No LOAD segments found");

  (* Find DYNAMIC segment *)
  let dynamic_segment =
    Array.find_opt
      (fun prog -> match prog.p_type with `PT_DYNAMIC -> true | _ -> false)
      programs
  in

  match dynamic_segment with
  | Some dyn ->
      Alcotest.(check int64)
        "DYNAMIC segment virtual address" 0x1fda0L
        (Unsigned.UInt64.to_int64 dyn.p_vaddr);
      Alcotest.(check int64)
        "DYNAMIC segment file size" 0x1f0L
        (Unsigned.UInt64.to_int64 dyn.p_filesz)
  | None -> Alcotest.fail "Could not find DYNAMIC segment"

let test_elf_symbol_table hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let _header, sections = Elf.read_elf buffer in

  (* Find symbol table section *)
  let symtab_section =
    Array.find_opt (fun sec -> sec.sh_name_str = ".symtab") sections
  in

  (match symtab_section with
  | Some symtab ->
      Alcotest.(check int64)
        ".symtab section size" 0x840L
        (Unsigned.UInt64.to_int64 symtab.sh_size);
      Alcotest.(check int)
        ".symtab section type (SYMTAB)" 2
        (Unsigned.UInt32.to_int symtab.sh_type)
  | None -> Alcotest.fail "Could not find .symtab section");

  (* Find string table section *)
  let strtab_section =
    Array.find_opt (fun sec -> sec.sh_name_str = ".strtab") sections
  in

  match strtab_section with
  | Some strtab ->
      Alcotest.(check int64)
        ".strtab section size" 0x233L
        (Unsigned.UInt64.to_int64 strtab.sh_size);
      Alcotest.(check int)
        ".strtab section type (STRTAB)" 3
        (Unsigned.UInt32.to_int strtab.sh_type)
  | None -> Alcotest.fail "Could not find .strtab section"

let test_elf_dynamic_section hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let _header, sections = Elf.read_elf buffer in

  (* Find dynamic section *)
  let dynamic_section =
    Array.find_opt (fun sec -> sec.sh_name_str = ".dynamic") sections
  in

  match dynamic_section with
  | Some dyn ->
      Alcotest.(check int64)
        ".dynamic section size" 0x1f0L
        (Unsigned.UInt64.to_int64 dyn.sh_size);
      Alcotest.(check int64)
        ".dynamic section address" 0x1fda0L
        (Unsigned.UInt64.to_int64 dyn.sh_addr);
      Alcotest.(check int)
        ".dynamic section type (DYNAMIC)" 6
        (Unsigned.UInt32.to_int dyn.sh_type)
  | None -> Alcotest.fail "Could not find .dynamic section"

let test_elf_section_contents hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let _header, sections = Elf.read_elf buffer in

  (* Find .rodata section and read its contents *)
  let rodata_section =
    Array.find_opt (fun sec -> sec.sh_name_str = ".rodata") sections
  in

  match rodata_section with
  | Some rodata ->
      let content =
        Bigarray.Array1.sub buffer
          (Unsigned.UInt64.to_int rodata.sh_offset)
          (Unsigned.UInt64.to_int rodata.sh_size)
      in

      (* Check that we can read the content *)
      Alcotest.(check bool)
        "Can read .rodata content" true
        (Bigarray.Array1.dim content > 0);

      (* The .rodata section should contain "Hello, World!" string *)
      let has_hello = ref false in
      for i = 0 to min (Bigarray.Array1.dim content - 13) 12 do
        if
          Bigarray.Array1.get content i = Char.code 'H'
          && Bigarray.Array1.get content (i + 1) = Char.code 'e'
          && Bigarray.Array1.get content (i + 2) = Char.code 'l'
          && Bigarray.Array1.get content (i + 3) = Char.code 'l'
          && Bigarray.Array1.get content (i + 4) = Char.code 'o'
        then has_hello := true
      done;
      Alcotest.(check bool) "Contains 'Hello' string" true !has_hello
  | None -> Alcotest.fail "Could not find .rodata section"

let binary_path =
  let doc = "Path to the ELF binary file to test" in
  Cmdliner.Arg.(
    required & opt (some file) None & info [ "binary"; "b" ] ~doc ~docv:"BINARY")

let () =
  Alcotest.run_with_args "ELF Tests" binary_path
    [
      ( "header",
        [ ("parse ELF header correctly", `Quick, test_elf_header_parsing) ] );
      ( "sections",
        [
          ("parse ELF sections correctly", `Quick, test_elf_sections);
          ("read section contents", `Quick, test_elf_section_contents);
        ] );
      ( "program_headers",
        [
          ("parse program headers correctly", `Quick, test_elf_program_headers);
        ] );
      ("symbol_table", [ ("parse symbol table", `Quick, test_elf_symbol_table) ]);
      ( "dynamic",
        [ ("parse dynamic section", `Quick, test_elf_dynamic_section) ] );
    ]
