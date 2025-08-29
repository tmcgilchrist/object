open Types

type identification = {
  elf_class : u8;
  elf_data : u8;
  elf_version : u8;
  elf_osabi : u8;
  elf_abiversion : u8;
}

type header = {
  e_ident : identification; (* ELF "magic number" *)
  e_type : u16; (* Executable, shared lib, relocatable, core. *)
  e_machine : u16; (* Architecture, e.g., EM_X86_64 for x64 *)
  e_version : u32; (* Version, must be 1 *)
  e_entry : u64; (* Entry point virtual address *)
  e_phoff : u64; (* Program header table file offset *)
  e_shoff : u64; (* Section header table file offset *)
  e_flags : u32; (* Processor-specific flags *)
  e_ehsize : u16; (* ELF header size *)
  e_phentsize : u16; (* Program header size *)
  e_phnum : u16; (* Number of program headers *)
  e_shentsize : u16; (* Section header size *)
  e_shnum : u16; (* Number of section headers *)
  e_shstrndx : u16; (* Section that holds the string table *)
}

type section_type =
  [ `SHT_NULL
  | `SHT_PROGBITS
  | `SHT_SYMTAB
  | `SHT_STRTAB
  | `SHT_RELA
  | `SHT_HASH
  | `SHT_DYNAMIC
  | `SHT_NOTE
  | `SHT_NOBITS
  | `SHT_REL
  | `SHT_SHLIB
  | `SHT_DYNSYM
  | `SHT_INIT_ARRAY
  | `SHT_FINI_ARRAY
  | `SHT_PREINIT_ARRAY
  | `SHT_GROUP
  | `SHT_SYMTAB_SHNDX
  | `SHT_RELR
  | `SHT_LOOS
  | `SHT_LLVM_DEPENDENT_LIBRARIES
  | `SHT_GNU_ATTRIBUTES
  | `SHT_GNU_HASH
  | `SHT_GNU_LIBLIST
  | `SHT_CHECKSUM
  | `SHT_LOSUNW
  | `SHT_SUNW_move
  | `SHT_SUNW_COMDAT
  | `SHT_SUNW_syminfo
  | `SHT_GNU_VERDEF
  | `SHT_GNU_VERNEED
  | `SHT_GNU_VERSYM
  | `SHT_HISUNW
  | `SHT_HIOS
  | `SHT_LOPROC
  | `SHT_HIPROC
  | `SHT_LOUSER
  | `SHT_HIUSER ]

type section_flags =
  [ `SHF_WRITE
  | `SHF_ALLOC
  | `SHF_EXECINSTR
  | `SHF_MERGE
  | `SHF_STRINGS
  | `SHF_INFO_LINK
  | `SHF_LINK_ORDER
  | `SHF_OS_NONCONFORMING
  | `SHF_GROUP
  | `SHF_TLS
  | `SHF_COMPRESSED
  | `SHF_MASKOS
  | `SHF_MASKPROC
  | `SHF_ORDERED
  | `SHF_EXCLUDE ]
(** Values for [section.sh_flags]. *)

type section = {
  sh_name : u32; (* Section name as string table index *)
  sh_name_str : string; (* Section name *)
  sh_type : u32; (* Type, e.g., code, string/symbol table *)
  sh_flags : u64; (* Section attributes, e.g., writable during execution *)
  sh_addr : u64; (* Virtual load address *)
  sh_offset : u64; (* File offset *)
  sh_size : u64; (* Section size in bytes *)
  sh_link : u32; (* Index of an associated section *)
  sh_info : u32; (* Additional info, e.g., section group info *)
  sh_addralign : u64; (* Section alignment *)
  sh_entsize : u64; (* Entry size if the section holds a table *)
}

(*  Legal values for p_type (segment type). *)
type program_type =
  [ `PT_NULL
  | `PT_LOAD
  | `PT_DYNAMIC
  | `PT_INTERP
  | `PT_NOTE
  | `PT_SHLIB
  | `PT_PHDR
  | `PT_TLS
  | `PT_NUM
  | `PT_LOOS
  | `PT_GNU_EH_FRAME
  | `PT_GNU_STACK
  | `PT_GNU_RELRO
  | `PT_GNU_PROPERTY
  | `PT_GNU_SFRAME
  | `PT_LOSUNW
  | `PT_SUNWBSS
  | `PT_SUNWSTACK
  | `PT_HISUNW
  | `PT_HIOS
  | `PT_LOPROC
  | `PT_HIPROC ]

(* Legal values for p_flags (segment flags). *)
type program_flags = [ `PF_X | `PF_W | `PF_R | `PF_RX | `PF_RW | `PF_WX | `PF_RWX | `PF_MASKOS | `PF_MASKPROC ]

type program = {
  p_type : program_type;
  p_flags : program_flags;
  p_offset : u64;
  p_vaddr : u64;
  p_paddr : u64;
  p_filesz : u64;
  p_memsz : u64;
  p_align : u64;
}

type entry_type =
  [ `AT_NULL
  | `AT_IGNORE
  | `AT_EXECFD
  | `AT_PHDR
  | `AT_PHENT
  | `AT_PHNUM
  | `AT_PAGESZ
  | `AT_BASE
  | `AT_FLAGS
  | `AT_ENTRY
  | `AT_NOTELF
  | `AT_UID
  | `AT_EUID
  | `AT_GID
  | `AT_EGID
  | `AT_CLKTCK ]

type auxiliary_vector = { a_type : entry_type; a_val : u64 }

open Buffer

let entry_type (x : u64) =
  match Unsigned.UInt64.to_int x with
  | 0 -> `AT_NULL
  | 1 -> `AT_IGNORE
  | 2 -> `AT_EXECFD
  | 3 -> `AT_PHDR
  | 4 -> `AT_PHENT
  | 5 -> `AT_PHNUM
  | 6 -> `AT_PAGESZ
  | 7 -> `AT_BASE
  | 8 -> `AT_FLAGS
  | 9 -> `AT_ENTRY
  | 10 -> `AT_NOTELF
  | 11 -> `AT_UID
  | 12 -> `AT_EUID
  | 13 -> `AT_GID
  | 14 -> `AT_EGID
  | 15 -> `AT_CLKTCK
  | s -> invalid_format (Printf.sprintf "Unrecognised entry_type value %d" s)

(* When the process is started, the auxiliary vector is put in memory just above the
   program stack. Helpfully, Linux provides the same data in the /proc/<pid>/auxv
   file.

   Provide the contents of either in [buf].

   Also available using https://www.man7.org/linux/man-pages/man3/getauxval.3.html or
   by defining C main as
   `int main(int argc, char *argv[ ], char *envp[ ], ElfW(auxv_t) *auxvec)`
*)
let read_auxiliary_vector (buf : Buffer.t) : auxiliary_vector list =
  let rec go buf acc =
    let a_type = entry_type (Read.u64 buf) in
    if a_type == `AT_NULL then acc
    else
      let a_val = Read.u64 buf in
      go buf ({ a_type; a_val } :: acc)
  in
  let aux_v = cursor buf in
  go aux_v []

let program_type x =
  match Unsigned.UInt32.to_int x with
  | 0 -> `PT_NULL
  | 1 -> `PT_LOAD
  | 2 -> `PT_DYNAMIC
  | 3 -> `PT_INTERP
  | 4 -> `PT_NOTE
  | 5 -> `PT_SHLIB
  | 6 -> `PT_PHDR
  | 7 -> `PT_TLS
  | 8 -> `PT_NUM
  | 0x60000000 -> `PT_LOOS
  | 0x6474e550 -> `PT_GNU_EH_FRAME
  | 0x6474e551 -> `PT_GNU_STACK
  | 0x6474e552 -> `PT_GNU_RELRO
  | 0x6474e553 -> `PT_GNU_PROPERTY
  | 0x6474e554 -> `PT_GNU_SFRAME
  (* These Solaris ELF specific pieces are probably unnecessary but
     are kept for completeness. We're targeting Linux and FreeBSD systems.
  *)
  | 0x6ffffffa -> `PT_LOSUNW
  (* | 0x6ffffffa -> `PT_SUNWBSS *)
  | 0x6ffffffb -> `PT_SUNWSTACK
  | 0x6fffffff -> `PT_HISUNW
  (* | 0x6fffffff -> `PT_HIOS *)
  | 0x70000000 -> `PT_LOPROC
  | 0x7fffffff -> `PT_HIPROC
  | s -> invalid_format (Printf.sprintf "Unrecognised program_type value %x" s)

let program_flags x =
  let flags = Unsigned.UInt32.to_int x in
  match flags with
  | 0x00000001 -> `PF_X (* (1 << 0) *)
  | 0x00000002 -> `PF_W (* (1 << 1) *)
  | 0x00000003 -> `PF_WX (* W+X combination *)
  | 0x00000004 -> `PF_R (* (1 << 2) *)
  | 0x00000005 -> `PF_RX (* R+X combination *)
  | 0x00000006 -> `PF_RW (* R+W combination *)
  | 0x00000007 -> `PF_RWX (* R+W+X combination *)
  | 0x0ff00000 -> `PF_MASKOS
  | 0xf0000000 -> `PF_MASKPROC
  | s -> invalid_format (Printf.sprintf "Unrecognised program_flags value %x" s)

let read_magic t =
  ensure t 4 "Magic number truncated";
  let { buffer; position } = t in
  let valid =
    buffer.{position + 0} = 0x7f
    && buffer.{position + 1} = Char.code 'E'
    && buffer.{position + 2} = Char.code 'L'
    && buffer.{position + 3} = Char.code 'F'
  in
  if not valid then invalid_format "No ELF magic number";
  advance t 4

let elfclass64 = Unsigned.UInt8.of_int 2

let read_identification t =
  ensure t 12 "Identification truncated";
  let elf_class = Read.u8 t in
  let elf_data = Read.u8 t in
  let elf_version = Read.u8 t in
  let elf_osabi = Read.u8 t in
  let elf_abiversion = Read.u8 t in
  let zero = Unsigned.UInt8.of_int 0 in
  if
    not
      (Read.u8 t = zero
      && Read.u8 t = zero
      && Read.u8 t = zero
      && Read.u8 t = zero
      && Read.u8 t = zero
      && Read.u8 t = zero
      && Read.u8 t = zero)
  then invalid_format "Incorrect padding after identification";
  if elf_class != elfclass64 then
    failwith "object only supports ELFCLASS64 (64-bit object) files";
  { elf_class; elf_data; elf_version; elf_osabi; elf_abiversion }

let read_header t e_ident =
  assert (t.position = 16);
  ensure t 48 "Header truncated";
  let e_type = Read.u16 t in
  let e_machine = Read.u16 t in
  let e_version = Read.u32 t in
  let e_entry = Read.u64 t in
  let e_phoff = Read.u64 t in
  let e_shoff = Read.u64 t in
  let e_flags = Read.u32 t in
  let e_ehsize = Read.u16 t in
  let e_phentsize = Read.u16 t in
  let e_phnum = Read.u16 t in
  let e_shentsize = Read.u16 t in
  let e_shnum = Read.u16 t in
  let e_shstrndx = Read.u16 t in
  {
    e_type;
    e_machine;
    e_version;
    e_entry;
    e_phoff;
    e_shoff;
    e_flags;
    e_ehsize;
    e_phentsize;
    e_phnum;
    e_shentsize;
    e_shnum;
    e_shstrndx;
    e_ident;
  }

let read_section header t n =
  seek t
    (Unsigned.UInt64.to_int header.e_shoff
    + (n * Unsigned.UInt16.to_int header.e_shentsize));
  ensure t 64 "Shdr truncated";
  let sh_name = Read.u32 t in
  let sh_type = Read.u32 t in
  let sh_flags = Read.u64 t in
  let sh_addr = Read.u64 t in
  let sh_offset = Read.u64 t in
  let sh_size = Read.u64 t in
  let sh_link = Read.u32 t in
  let sh_info = Read.u32 t in
  let sh_addralign = Read.u64 t in
  let sh_entsize = Read.u64 t in
  {
    sh_name;
    sh_type;
    sh_flags;
    sh_addr;
    sh_offset;
    sh_size;
    sh_link;
    sh_info;
    sh_addralign;
    sh_entsize;
    sh_name_str = "";
  }

let read_section_name shstrndx t shdr =
  let n = Unsigned.UInt32.to_int shdr.sh_name in
  seek t (Unsigned.UInt64.to_int shstrndx.sh_offset + n);
  match
    Read.zero_string t ~maxlen:(Unsigned.UInt64.to_int shstrndx.sh_size - n) ()
  with
  | None -> invalid_format "Unterminated section name"
  | Some s -> s

let read_sections header t =
  let sections =
    Array.init (Unsigned.UInt16.to_int header.e_shnum) (read_section header t)
  in
  let shstrndx = sections.(Unsigned.UInt16.to_int header.e_shstrndx) in
  Array.map
    (fun s -> { s with sh_name_str = read_section_name shstrndx t s })
    sections

let read_elf buffer =
  let elf = cursor buffer in
  read_magic elf;
  let e_ident = read_identification elf in
  let header = read_header elf e_ident in
  (header, read_sections header elf)

let read_program header t n =
  seek t
    (Unsigned.UInt64.to_int header.e_phoff
    + (n * Unsigned.UInt16.to_int header.e_phentsize));
  ensure t 48 "Phdr truncated";
  let p_type = program_type (Read.u32 t) in
  let p_flags = program_flags (Read.u32 t) in
  let p_offset = Read.u64 t in
  let p_vaddr = Read.u64 t in
  let p_paddr = Read.u64 t in
  let p_filesz = Read.u64 t in
  let p_memsz = Read.u64 t in
  let p_align = Read.u64 t in
  { p_type; p_flags; p_offset; p_vaddr; p_paddr; p_filesz; p_memsz; p_align }

let read_programs buf header =
  let elf = cursor buf in
  Array.init (Unsigned.UInt16.to_int header.e_phnum) (read_program header elf)

exception Found of section

let find_section sections name =
  try
    Array.iter
      (fun section -> if section.sh_name_str = name then raise (Found section))
      sections;
    None
  with Found section -> Some section

let section_body buffer shdr =
  Bigarray.Array1.sub buffer
    (Unsigned.UInt64.to_int shdr.sh_offset)
    (Unsigned.UInt64.to_int shdr.sh_size)

let read_section_contents buf sections section_name =
  match find_section sections section_name with
  | None -> None
  | Some section -> Some (section_body buf section)
