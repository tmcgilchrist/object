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

  (* Test section header count *)
  Alcotest.(check bool)
    "Has sections" true
    (Unsigned.UInt16.to_int header.e_shnum > 0)

let find_section sections name =
  match Array.find_opt (fun sec -> sec.sh_name_str = name) sections with
  | Some sec -> sec
  | None -> Alcotest.failf "Could not find %s section" name

let load_segments programs =
  Array.to_list programs
  |> List.filter (fun prog ->
      match prog.p_type with `PT_LOAD -> true | _ -> false)

let is_executable prog =
  match prog.p_flags with
  | `PF_X | `PF_RX | `PF_WX | `PF_RWX -> true
  | `PF_R | `PF_W | `PF_RW | `PF_MASKOS | `PF_MASKPROC -> false

(* [addr, addr + size) lies within the segment's memory image. *)
let segment_contains prog addr size =
  let start = Unsigned.UInt64.to_int prog.p_vaddr in
  addr >= start && addr + size <= start + Unsigned.UInt64.to_int prog.p_memsz

let section_is_loaded programs sec =
  List.exists
    (fun prog ->
      segment_contains prog
        (Unsigned.UInt64.to_int sec.sh_addr)
        (Unsigned.UInt64.to_int sec.sh_size))
    (load_segments programs)

let test_elf_entry_point hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let header, sections = Elf.read_elf buffer in
  let text = find_section sections ".text" in
  let entry = Unsigned.UInt64.to_int header.e_entry in
  let text_start = Unsigned.UInt64.to_int text.sh_addr in
  Alcotest.(check bool)
    "Entry point lies within .text" true
    (entry >= text_start
    && entry < text_start + Unsigned.UInt64.to_int text.sh_size)

let test_elf_sections hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let header, sections = Elf.read_elf buffer in
  let programs = Elf.read_programs buffer header in

  Alcotest.(check bool) "Has multiple sections" true (Array.length sections > 20);

  let check_section name sh_type =
    let sec = find_section sections name in
    Alcotest.(check int)
      (name ^ " section type") sh_type
      (Unsigned.UInt32.to_int sec.sh_type);
    Alcotest.(check bool)
      (name ^ " lies within a LOAD segment")
      true
      (section_is_loaded programs sec);
    sec
  in

  let text =
    check_section ".text" 1
    (* PROGBITS *)
  in
  Alcotest.(check bool)
    ".text is non-empty" true
    (Unsigned.UInt64.to_int text.sh_size > 0);
  Alcotest.(check bool)
    ".text lies within an executable segment" true
    (List.exists
       (fun prog ->
         is_executable prog
         && segment_contains prog
              (Unsigned.UInt64.to_int text.sh_addr)
              (Unsigned.UInt64.to_int text.sh_size))
       (load_segments programs));

  let rodata =
    check_section ".rodata" 1
    (* PROGBITS *)
  in
  Alcotest.(check bool)
    ".rodata holds the greeting" true
    (Unsigned.UInt64.to_int rodata.sh_size >= String.length "Hello, World!\n");

  ignore (check_section ".data" 1 (* PROGBITS *));
  ignore (check_section ".bss" 8 (* NOBITS *))

let test_elf_program_headers hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let header, sections = Elf.read_elf buffer in
  let programs = Elf.read_programs buffer header in

  Alcotest.(check int)
    "Program header count matches e_phnum"
    (Unsigned.UInt16.to_int header.e_phnum)
    (Array.length programs);

  let loads = load_segments programs in
  Alcotest.(check bool) "Has LOAD segments" true (loads <> []);
  Alcotest.(check bool)
    "Has an executable LOAD segment" true
    (List.exists is_executable loads);
  List.iter
    (fun prog ->
      Alcotest.(check bool)
        "LOAD segment file size fits in memory size" true
        (Unsigned.UInt64.to_int prog.p_filesz
        <= Unsigned.UInt64.to_int prog.p_memsz))
    loads;

  (* PT_DYNAMIC describes the same bytes as the .dynamic section. *)
  let dynamic = find_section sections ".dynamic" in
  match
    Array.find_opt
      (fun prog -> match prog.p_type with `PT_DYNAMIC -> true | _ -> false)
      programs
  with
  | Some dyn ->
      Alcotest.(check int64)
        "DYNAMIC segment address matches .dynamic"
        (Unsigned.UInt64.to_int64 dynamic.sh_addr)
        (Unsigned.UInt64.to_int64 dyn.p_vaddr);
      Alcotest.(check int64)
        "DYNAMIC segment size matches .dynamic"
        (Unsigned.UInt64.to_int64 dynamic.sh_size)
        (Unsigned.UInt64.to_int64 dyn.p_filesz)
  | None -> Alcotest.fail "Could not find DYNAMIC segment"

let test_elf_symbol_table hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let header, sections = Elf.read_elf buffer in

  let symtab = find_section sections ".symtab" in
  Alcotest.(check int)
    ".symtab section type (SYMTAB)" 2
    (Unsigned.UInt32.to_int symtab.sh_type);
  Alcotest.(check int)
    ".symtab entry size" 24
    (Unsigned.UInt64.to_int symtab.sh_entsize);
  Alcotest.(check int)
    ".symtab size is a whole number of entries" 0
    (Unsigned.UInt64.to_int symtab.sh_size mod 24);

  let strtab = find_section sections ".strtab" in
  Alcotest.(check int)
    ".strtab section type (STRTAB)" 3
    (Unsigned.UInt32.to_int strtab.sh_type);
  Alcotest.(check string)
    ".symtab links to .strtab" ".strtab"
    sections.(Unsigned.UInt32.to_int symtab.sh_link).sh_name_str;

  let symbols = Elf.read_symbol_table buffer header sections in
  Alcotest.(check int)
    "One symbol per .symtab entry"
    (Unsigned.UInt64.to_int symtab.sh_size / 24)
    (Array.length symbols);
  Alcotest.(check bool)
    "main is a function symbol" true
    (Array.exists
       (fun sym ->
         sym.st_name_str = "main"
         && match sym.st_type with `STT_FUNC -> true | _ -> false)
       symbols)

let test_elf_dynamic_section hello_world_path =
  let buffer = Buffer.parse hello_world_path in
  let _header, sections = Elf.read_elf buffer in
  let dynamic = find_section sections ".dynamic" in
  Alcotest.(check int)
    ".dynamic section type (DYNAMIC)" 6
    (Unsigned.UInt32.to_int dynamic.sh_type);
  Alcotest.(check int)
    ".dynamic entry size" 16
    (Unsigned.UInt64.to_int dynamic.sh_entsize);
  Alcotest.(check bool)
    ".dynamic size is a non-empty whole number of entries" true
    (Unsigned.UInt64.to_int dynamic.sh_size > 0
    && Unsigned.UInt64.to_int dynamic.sh_size mod 16 = 0)

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
        [
          ("parse ELF header correctly", `Quick, test_elf_header_parsing);
          ("entry point lies within .text", `Quick, test_elf_entry_point);
        ] );
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
