open Types

(** Linux ELF parser based on /usr/include/elf.h *)

type identification = {
  elf_class      : u8;
  elf_data       : u8;
  elf_version    : u8;
  elf_osabi      : u8;
  elf_abiversion : u8;
}

type header = {
  e_ident     : identification; (* ELF "magic number" *)
  e_type      : u16;            (* Executable, shared lib, relocatable, core. *)
  e_machine   : u16;            (* Architecture, e.g., EM_X86_64 for x64 *)
  e_version   : u32;            (* Version, must be 1 *)
  e_entry     : u64;            (* Entry point virtual address *)
  e_phoff     : u64;            (* Program header table file offset *)
  e_shoff     : u64;            (* Section header table file offset *)
  e_flags     : u32;            (* Processor-specific flags *)
  e_ehsize    : u16;            (* ELF header size *)
  e_phentsize : u16;            (* Program header size *)
  e_phnum     : u16;            (* Number of program headers *)
  e_shentsize : u16;            (* Section header size *)
  e_shnum     : u16;            (* Number of section headers *)
  e_shstrndx  : u16;            (* Section that holds the string table *)
}

(* Value for [section.sh_type]. *)
type section_type = [
  | `SHT_NULL (** Section header table entry is unused. *)
  | `SHT_PROGBITS (** Program data. *)
  | `SHT_SYMTAB (** Symbol table. *)
  | `SHT_STRTAB (** String table. *)
  | `SHT_RELA (** Relocation entries with explicit addends. *)
  | `SHT_HASH (** Symbol hash table. *)
  | `SHT_DYNAMIC (** Dynamic linking information. *)
  | `SHT_NOTE (** Notes. *)
  | `SHT_NOBITS (** Program space with no data (bss). *)
  | `SHT_REL (** Relocation entries without explicit addends. *)
  | `SHT_SHLIB (** Reserved section type. *)
  | `SHT_DYNSYM (** Dynamic linker symbol table. *)
  | `SHT_INIT_ARRAY (** Array of constructors. *)
  | `SHT_FINI_ARRAY (** Array of destructors. *)
  | `SHT_PREINIT_ARRAY (** Array of pre-constructors. *)
  | `SHT_GROUP (** Section group. *)
  | `SHT_SYMTAB_SHNDX (** Extended section indices for a symbol table. *)
  | `SHT_RELR (** Relocation entries; only offsets. *)
  | `SHT_LOOS (** Start of OS-specific section types. *)
  | `SHT_LLVM_DEPENDENT_LIBRARIES (** LLVM-style dependent libraries. *)
  | `SHT_GNU_ATTRIBUTES (** Object attributes *)
  | `SHT_GNU_HASH (** GNU-style hash table. *)
  | `SHT_GNU_LIBLIST (** Prelink library list. *)
  | `SHT_CHECKSUM (** Checksum for DSO content. *)
  | `SHT_LOSUNW (** Sun-specific low bound. *)
  | `SHT_SUNW_move
  | `SHT_SUNW_COMDAT
  | `SHT_SUNW_syminfo
  | `SHT_GNU_VERDEF (** Version definition section. *)
  | `SHT_GNU_VERNEED (** Version needs section. *)
  | `SHT_GNU_VERSYM (** Version symbol table. *)
  | `SHT_HISUNW (** Sun-specific high bound. *)
  | `SHT_HIOS (** End of OS-specific section types. *)
  | `SHT_LOPROC (** Start of processor-specific section types. *)
  | `SHT_HIPROC (** End of processor-specific section types. *)
  | `SHT_LOUSER (** Start of application-specific section types. *)
  | `SHT_HIUSER (** End of application-specific section types. *)
  ]

(** Values for [section.sh_flags].  *)
type section_flags = [
  | `SHF_WRITE (** Writable  *)
  | `SHF_ALLOC (** Occupies memory during execution  *)
  | `SHF_EXECINSTR (** Executable *)
  | `SHF_MERGE (** Might be merged *)
  | `SHF_STRINGS (** Contains nul-terminated strings *)
  | `SHF_INFO_LINK (** `sh_info' contains SHT index *)
  | `SHF_LINK_ORDER (** Preserve order after combining  *)
  | `SHF_OS_NONCONFORMING (** Non-standard OS specific handling required *)
  | `SHF_GROUP (** Section is member of a group. *)
  | `SHF_TLS (** Section hold thread-local data.  *)
  | `SHF_COMPRESSED (** Section with compressed data. *)
  | `SHF_MASKOS (** OS-specific. *)
  | `SHF_MASKPROC (** Processor-specific  *)
  | `SHF_ORDERED (** Special ordering requirement (Solaris). *)
  | `SHF_EXCLUDE (** Section is excluded unless referenced or allocated (Solaris). *)
  ]

type section = {
  sh_name      : u32;           (* Section name as string table index *)
  sh_name_str  : string;        (* Section name *)
  sh_type      : u32;           (* Type, e.g., code, string/symbol table *)
  sh_flags     : u64;           (* Section attributes, e.g., writable during execution *)
  sh_addr      : u64;           (* Virtual load address *)
  sh_offset    : u64;           (* File offset *)
  sh_size      : u64;           (* Section size in bytes *)
  sh_link      : u32;           (* Index of an associated section *)
  sh_info      : u32;           (* Additional info, e.g., section group info *)
  sh_addralign : u64;           (* Section alignment *)
  sh_entsize   : u64;           (* Entry size if the section holds a table *)
}

(** Legal values for [p_type] field of [program] (segment type).*)
type program_type = [
  | `PT_NULL         (** Program header table entry is unused. *)
  | `PT_LOAD         (** Specifies a segment to load into memory at the given file address. *)
  | `PT_DYNAMIC      (** Dynamic linking information. *)
  | `PT_INTERP       (** Specifies the location and size of the path to the dynamic linker. *)
  | `PT_NOTE         (** The location and size of auxiliary information about the binary.  *)
  | `PT_SHLIB        (** Reserved *)
  | `PT_PHDR         (** Location to load the program headers  *)
  | `PT_TLS          (** Thread-local storage. *)
  | `PT_NUM          (** Number of defined types *)
  | `PT_LOOS         (** Start of OS-specific *)
  | `PT_GNU_EH_FRAME (** The stack unwinding information (points to the same memory as .eh_frame section). *)
  | `PT_GNU_STACK    (** Indicates stack executability, specific to the Linux kernel  *)
  | `PT_GNU_RELRO    (** Read-only after relocation. *)
  | `PT_GNU_PROPERTY (** Special note with dynamic linker specific information (.note.gnu.property) *)
  | `PT_GNU_SFRAME   (** SFrame segment. *)
  | `PT_LOSUNW
  | `PT_SUNWBSS      (** Sun Specific segment *)
  | `PT_SUNWSTACK    (** Stack segment *)
  | `PT_HISUNW
  | `PT_HIOS         (** End of OS-specific *)
  | `PT_LOPROC       (** Start of processor-specific *)
  | `PT_HIPROC       (** End of processor-specific *)
]

(* Legal values for p_flags (segment flags).  *)
type program_flags = [
  | `PF_X          (** Segment is executable *)
  | `PF_W          (** Segment is writable *)
  | `PF_R          (** Segment is readable *)
  | `PF_MASKOS     (** OS-specific *)
  | `PF_MASKPROC   (** Processor-specific *)
]

(** Program headers describe the segments of the program relevant to program loading. *)
type program = {
  p_type   : program_type;      (** Segment type *)
  p_flags  : program_flags;     (** Segment flags *)
  p_offset : u64;               (** Segment file offset *)
  p_vaddr  : u64;               (** Segment virtual address *)
  p_paddr  : u64;               (** Segment physical address *)
  p_filesz : u64;               (** Segment size in file *)
  p_memsz  : u64;               (** Segment size in memory *)
  p_align  : u64;               (** Segment alignment *)
}

(** Auxiliary vector *)

type entry_type = [
  | `AT_NULL         (** End of vector *)
  | `AT_IGNORE       (** Entry should be ignored *)
  | `AT_EXECFD       (** File descriptor of program  *)
  | `AT_PHDR         (** Program headers for program *)
  | `AT_PHENT        (** Size of program header entry *)
  | `AT_PHNUM        (** Number of program headers *)
  | `AT_PAGESZ       (** System page size *)
  | `AT_BASE         (** Base address of interpreter *)
  | `AT_FLAGS        (** Flags *)
  | `AT_ENTRY        (** Entry point of program *)
  | `AT_NOTELF       (** Program is not ELF *)
  | `AT_UID          (** Real uid *)
  | `AT_EUID         (** Effective uid *)
  | `AT_GID          (** Real gid *)
  | `AT_EGID         (** Effective gid *)
  | `AT_CLKTCK       (** Frequency of times() *)
  ]

type auxiliary_vector = {
  a_type : entry_type;   (** Entry type *)
  a_val : u64;           (** Integer value *)
}

(** [read_elf buffer] decodes the header and section table
    from a buffer pointing to an ELF image. *)
val read_elf : Buffer.t -> header * section array

(** [read_programs buffer header] decodes the program headers
    from a buffer pointing to an ELF image. *)
val read_programs : Buffer.t -> header -> program array

(** [read_auxiliary_vector buffer] decodes the auxiliary vector
    form [buffer], which can be provided from /proc/<pid>/auxv or
    at the high end of the address space above the environment
    variables (according to the System V Application Binary Interface).
    https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf

    Exactly where the auxv appears in memory is platform specific,
    consult the platform ELF ABI documents for details.

    The auxiliary vector is intended for passing information from
    the operating system to a program interpreter,
    such as /lib/ld-lsb-ia64.so.1.
 *)
val read_auxiliary_vector : Buffer.t -> auxiliary_vector list

(** [read_section_contents buf section_name] reads the section contents for [section_name].
    Returns None if the section name is not found *)
val read_section_contents : Buffer.t -> section array -> string -> Buffer.t option