open Types

type arch =
  [ `X86 | `X86_64 | `ARM | `ARM64 | `POWERPC | `POWERPC64 | `Unknown of int ]

type format = ELF | MACHO

type section = {
  name : string;
  size : u64;
  address : u64;
  offset : u64 option;
  section_type : string;
}

type segment = {
  name : string;
  virtual_address : u64;
  virtual_size : u64;
  file_offset : u64;
  file_size : u64;
  sections : section array;
}

type header = {
  format : format;
  architecture : arch;
  entry_point : u64 option;
  is_executable : bool;
  is_64bit : bool;
}

type t = {
  header : header;
  segments : segment array;
  all_sections : section array;
}

(** Convert Mach-O CPU type to generic arch *)
let macho_cpu_type_to_arch = function
  | `X86 -> `X86
  | `X86_64 -> `X86_64
  | `ARM -> `ARM
  | `ARM64 -> `ARM64
  | `ARM64_32 -> `ARM64 (* Treat ARM64_32 as ARM64 *)
  | `POWERPC -> `POWERPC
  | `POWERPC64 -> `POWERPC64
  | `Unknown n -> `Unknown n

(** Convert ELF machine type to generic arch *)
let elf_machine_to_arch (machine : Elf.elf_machine) =
  match machine with
  | `EM_386 -> `X86
  | `EM_X86_64 -> `X86_64
  | `EM_ARM -> `ARM
  | `EM_AARCH64 -> `ARM64
  | `EM_PPC -> `POWERPC
  | `EM_PPC64 -> `POWERPC64
  | `EM_UNKNOWN n -> `Unknown n
  | _ -> `Unknown 0 (* For other known but unmapped architectures *)

(** Convert Mach-O section to generic section *)
let macho_section_to_generic (sec : Macho.section) : section =
  let section_type =
    match sec.sec_type with
    | `S_REGULAR -> "REGULAR"
    | `S_ZEROFILL -> "ZEROFILL"
    | `S_CSTRING_LITERALS -> "CSTRING"
    | `S_SYMBOL_STUBS -> "STUBS"
    | _ -> "OTHER"
  in
  {
    name = sec.sec_sectname;
    size = sec.sec_size;
    address = sec.sec_addr;
    offset = Some (Unsigned.UInt64.of_uint32 sec.sec_offset);
    section_type;
  }

(** Convert ELF section to generic section *)
let elf_section_to_generic (sec : Elf.section) : section =
  let section_type =
    match Unsigned.UInt32.to_int sec.sh_type with
    | 1 -> "PROGBITS"
    | 3 -> "STRTAB"
    | 8 -> "NOBITS"
    | _ -> "OTHER"
  in
  {
    name = sec.sh_name_str;
    size = sec.sh_size;
    address = sec.sh_addr;
    offset = Some sec.sh_offset;
    section_type;
  }

(** Convert Mach-O segment to generic segment *)
let macho_segment_to_generic (seg : Macho.segment) : segment =
  {
    name = seg.seg_segname;
    virtual_address = seg.seg_vmaddr;
    virtual_size = seg.seg_vmsize;
    file_offset = seg.seg_fileoff;
    file_size = seg.seg_filesize;
    sections = Array.map macho_section_to_generic seg.seg_sections;
  }

(** Detect file format from buffer *)
let detect_format (buf : Buffer.t) : format =
  let cursor = Buffer.cursor buf in
  let magic = Buffer.Read.u32 cursor in
  let magic_int = Unsigned.UInt32.to_int magic in
  match magic_int with
  | 0x7f454c46 -> ELF (* ELF magic: \x7fELF *)
  | 0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE ->
      MACHO (* Mach-O magics *)
  | _ -> failwith "Unsupported file format"

(** Parse Mach-O file *)
let parse_macho (buf : Buffer.t) : t =
  let header, commands = Macho.read buf in

  let generic_header =
    {
      format = MACHO;
      architecture = macho_cpu_type_to_arch header.cpu_type;
      entry_point = None;
      (* Mach-O doesn't have a simple entry point *)
      is_executable =
        (match header.file_type with `EXECUTE -> true | _ -> false);
      is_64bit =
        (match header.magic with MAGIC64 | CIGAM64 -> true | _ -> false);
    }
  in

  let segments =
    List.fold_left
      (fun acc cmd ->
        match cmd with
        | Macho.LC_SEGMENT_64 (lazy seg) | Macho.LC_SEGMENT_32 (lazy seg) ->
            macho_segment_to_generic seg :: acc
        | _ -> acc)
      [] commands
    |> List.rev |> Array.of_list
  in

  let all_sections =
    Array.fold_left (fun acc seg -> Array.append acc seg.sections) [||] segments
  in

  { header = generic_header; segments; all_sections }

(** Parse ELF file *)
let parse_elf (buf : Buffer.t) : t =
  let elf_header, sections = Elf.read_elf buf in
  let programs = Elf.read_programs buf elf_header in

  let generic_header =
    {
      format = ELF;
      architecture = elf_machine_to_arch elf_header.e_machine;
      entry_point = Some elf_header.e_entry;
      is_executable =
        (match elf_header.e_type with
        | `ET_EXEC | `ET_DYN ->
            true (* Executable or position-independent executable *)
        | _ -> false);
      is_64bit =
        (match elf_header.e_ident.elf_class with
        | `ELFCLASS64 -> true
        | _ -> false);
    }
  in

  let generic_sections = Array.map elf_section_to_generic sections in

  (* Create segments from ELF program headers *)
  let segments =
    Array.map
      (fun (prog : Elf.program) ->
        let related_sections =
          Array.fold_left
            (fun acc sec ->
              if
                Unsigned.UInt64.compare sec.address prog.p_vaddr >= 0
                && Unsigned.UInt64.compare sec.address
                     (Unsigned.UInt64.add prog.p_vaddr prog.p_memsz)
                   < 0
              then sec :: acc
              else acc)
            [] generic_sections
          |> List.rev |> Array.of_list
        in

        {
          name =
            (match prog.p_type with
            | `PT_LOAD -> "LOAD"
            | `PT_DYNAMIC -> "DYNAMIC"
            | `PT_INTERP -> "INTERP"
            | `PT_NOTE -> "NOTE"
            | _ -> "OTHER");
          virtual_address = prog.p_vaddr;
          virtual_size = prog.p_memsz;
          file_offset = prog.p_offset;
          file_size = prog.p_filesz;
          sections = related_sections;
        })
      programs
  in

  { header = generic_header; segments; all_sections = generic_sections }

(** Main read function *)
let read (buf : Buffer.t) : t =
  match detect_format buf with ELF -> parse_elf buf | MACHO -> parse_macho buf

let sections t = t.all_sections
let segments t = t.segments

let find_section (t : t) name =
  Array.find_opt (fun (sec : section) -> sec.name = name) t.all_sections

let find_segment (t : t) name =
  Array.find_opt (fun (seg : segment) -> seg.name = name) t.segments

let section_contents buf (t : t) (section : section) =
  match (t.header.format, section.offset) with
  | MACHO, Some offset ->
      Bigarray.Array1.sub buf
        (Unsigned.UInt64.to_int offset)
        (Unsigned.UInt64.to_int section.size)
  | ELF, Some offset ->
      Bigarray.Array1.sub buf
        (Unsigned.UInt64.to_int offset)
        (Unsigned.UInt64.to_int section.size)
  | _, None -> invalid_arg "Section has no file offset"

let format t = t.header.format
let architecture t = t.header.architecture
let is_64bit t = t.header.is_64bit
let is_executable t = t.header.is_executable
