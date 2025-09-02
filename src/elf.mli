open Types

(** Linux ELF parser based on /usr/include/elf.h *)

type elf_class =
  [ `ELFCLASSNONE  (** Invalid class *)
  | `ELFCLASS32  (** 32-bit objects *)
  | `ELFCLASS64  (** 64-bit objects *) ]
(** ELF file class indicating the architecture word size. Determines the size of
    addresses and offsets throughout the ELF file format. *)

type elf_data =
  [ `ELFDATANONE  (** Invalid data encoding *)
  | `ELFDATA2LSB  (** 2's complement, little endian *)
  | `ELFDATA2MSB  (** 2's complement, big endian *) ]
(** ELF data encoding specifying the byte order used for multi-byte values
    within the ELF file. Affects interpretation of all integers and addresses in
    the file. *)

type elf_osabi =
  [ `ELFOSABI_NONE  (** UNIX System V ABI *)
  | `ELFOSABI_SYSV  (** Alias for ELFOSABI_NONE *)
  | `ELFOSABI_HPUX  (** HP-UX *)
  | `ELFOSABI_NETBSD  (** NetBSD *)
  | `ELFOSABI_GNU  (** Object uses GNU ELF extensions *)
  | `ELFOSABI_LINUX  (** Compatibility alias for GNU *)
  | `ELFOSABI_SOLARIS  (** Sun Solaris *)
  | `ELFOSABI_AIX  (** IBM AIX *)
  | `ELFOSABI_IRIX  (** SGI Irix *)
  | `ELFOSABI_FREEBSD  (** FreeBSD *)
  | `ELFOSABI_TRU64  (** Compaq TRU64 UNIX *)
  | `ELFOSABI_MODESTO  (** Novell Modesto *)
  | `ELFOSABI_OPENBSD  (** OpenBSD *)
  | `ELFOSABI_ARM_AEABI  (** ARM EABI *)
  | `ELFOSABI_ARM  (** ARM *)
  | `ELFOSABI_STANDALONE  (** Standalone (embedded) application *)
  | `ELFOSABI_UNKNOWN of int  (** Unknown OS ABI *) ]
(** ELF OS/ABI identification specifying the target operating system and ABI.
    Indicates which OS-specific extensions and conventions are used in the ELF
    file. *)

type elf_type =
  [ `ET_NONE  (** No file type *)
  | `ET_REL  (** Relocatable file *)
  | `ET_EXEC  (** Executable file *)
  | `ET_DYN  (** Shared object file *)
  | `ET_CORE  (** Core file *)
  | `ET_LOOS  (** OS-specific range start *)
  | `ET_HIOS  (** OS-specific range end *)
  | `ET_LOPROC  (** Processor-specific range start *)
  | `ET_HIPROC  (** Processor-specific range end *)
  | `ET_UNKNOWN of int  (** Unknown file type *) ]
(** ELF file type indicating the purpose and format of the ELF file. Determines
    how the file should be processed - whether it's an intermediate object file
    for linking, a complete executable, a shared library, or a core dump. *)

type elf_machine =
  [ `EM_NONE  (** No machine *)
  | `EM_M32  (** AT&T WE 32100 *)
  | `EM_SPARC  (** SUN SPARC *)
  | `EM_386  (** Intel 80386 *)
  | `EM_68K  (** Motorola m68k family *)
  | `EM_88K  (** Motorola m88k family *)
  | `EM_860  (** Intel 80860 *)
  | `EM_MIPS  (** MIPS R3000 big-endian *)
  | `EM_S370  (** IBM System/370 *)
  | `EM_MIPS_RS3_LE  (** MIPS R3000 little-endian *)
  | `EM_PARISC  (** HPPA *)
  | `EM_VPP500  (** Fujitsu VPP500 *)
  | `EM_SPARC32PLUS  (** Sun's "v8plus" *)
  | `EM_960  (** Intel 80960 *)
  | `EM_PPC  (** PowerPC *)
  | `EM_PPC64  (** PowerPC 64-bit *)
  | `EM_S390  (** IBM S390 *)
  | `EM_ARM  (** ARM *)
  | `EM_SH  (** Hitachi SH *)
  | `EM_SPARCV9  (** SPARC v9 64-bit *)
  | `EM_IA_64  (** Intel Merced *)
  | `EM_X86_64  (** AMD x86-64 architecture *)
  | `EM_AARCH64  (** ARM AARCH64 *)
  | `EM_RISCV (* RISC-V *)
  | `EM_UNKNOWN of int  (** Unknown machine type *) ]
(** ELF target machine architecture specification. Indicates the required
    architecture for the ELF file, determining instruction set compatibility and
    execution requirements. This field ensures that the file can only be
    executed on systems with compatible processor architectures. *)

type identification = {
  elf_class : elf_class;  (** Object file class (32-bit, 64-bit, etc.) *)
  elf_data : elf_data;  (** Data encoding (little-endian, big-endian) *)
  elf_version : u8;  (** ELF header version (must be 1) *)
  elf_osabi : elf_osabi;  (** Operating system/ABI identification *)
  elf_abiversion : u8;  (** ABI version *)
}
(** ELF identification structure from the e_ident field. Contains basic file
    format information including architecture class, byte order, and target
    operating system ABI. This is parsed from the first 16 bytes of an ELF file.
*)

type header = {
  e_ident : identification;  (** ELF identification and magic number *)
  e_type : elf_type;
      (** Object file type (executable, shared lib, relocatable, core) *)
  e_machine : elf_machine;  (** Target architecture (e.g., EM_X86_64 for x64) *)
  e_version : u32;  (** ELF version (must be 1) *)
  e_entry : u64;  (** Program entry point virtual address *)
  e_phoff : u64;  (** Program header table file offset *)
  e_shoff : u64;  (** Section header table file offset *)
  e_flags : u32;  (** Processor-specific flags *)
  e_ehsize : u16;  (** ELF header size in bytes *)
  e_phentsize : u16;  (** Size of a program header table entry *)
  e_phnum : u16;  (** Number of entries in program header table *)
  e_shentsize : u16;  (** Size of a section header table entry *)
  e_shnum : u16;  (** Number of entries in section header table *)
  e_shstrndx : u16;  (** Section header string table index *)
}
(** ELF header structure containing essential file metadata. This is the first
    structure in an ELF file and provides information needed to interpret the
    rest of the file, including table locations, entry points, and architecture
    details. *)

(* Value for [section.sh_type]. *)
type section_type =
  [ `SHT_NULL  (** Section header table entry is unused. *)
  | `SHT_PROGBITS  (** Program data. *)
  | `SHT_SYMTAB  (** Symbol table. *)
  | `SHT_STRTAB  (** String table. *)
  | `SHT_RELA  (** Relocation entries with explicit addends. *)
  | `SHT_HASH  (** Symbol hash table. *)
  | `SHT_DYNAMIC  (** Dynamic linking information. *)
  | `SHT_NOTE  (** Notes. *)
  | `SHT_NOBITS  (** Program space with no data (bss). *)
  | `SHT_REL  (** Relocation entries without explicit addends. *)
  | `SHT_SHLIB  (** Reserved section type. *)
  | `SHT_DYNSYM  (** Dynamic linker symbol table. *)
  | `SHT_INIT_ARRAY  (** Array of constructors. *)
  | `SHT_FINI_ARRAY  (** Array of destructors. *)
  | `SHT_PREINIT_ARRAY  (** Array of pre-constructors. *)
  | `SHT_GROUP  (** Section group. *)
  | `SHT_SYMTAB_SHNDX  (** Extended section indices for a symbol table. *)
  | `SHT_RELR  (** Relocation entries; only offsets. *)
  | `SHT_LOOS  (** Start of OS-specific section types. *)
  | `SHT_LLVM_DEPENDENT_LIBRARIES  (** LLVM-style dependent libraries. *)
  | `SHT_GNU_ATTRIBUTES  (** Object attributes *)
  | `SHT_GNU_HASH  (** GNU-style hash table. *)
  | `SHT_GNU_LIBLIST  (** Prelink library list. *)
  | `SHT_CHECKSUM  (** Checksum for DSO content. *)
  | `SHT_LOSUNW  (** Sun-specific low bound. *)
  | `SHT_SUNW_move
  | `SHT_SUNW_COMDAT
  | `SHT_SUNW_syminfo
  | `SHT_GNU_VERDEF  (** Version definition section. *)
  | `SHT_GNU_VERNEED  (** Version needs section. *)
  | `SHT_GNU_VERSYM  (** Version symbol table. *)
  | `SHT_HISUNW  (** Sun-specific high bound. *)
  | `SHT_HIOS  (** End of OS-specific section types. *)
  | `SHT_LOPROC  (** Start of processor-specific section types. *)
  | `SHT_HIPROC  (** End of processor-specific section types. *)
  | `SHT_LOUSER  (** Start of application-specific section types. *)
  | `SHT_HIUSER  (** End of application-specific section types. *) ]
(** ELF section type classification. Identifies the specific purpose and format
    of section contents, enabling proper interpretation by linkers, loaders, and
    debuggers. Different section types require different processing during
    linking and program loading. *)

type section_flags =
  [ `SHF_WRITE  (** Writable *)
  | `SHF_ALLOC  (** Occupies memory during execution *)
  | `SHF_EXECINSTR  (** Executable *)
  | `SHF_MERGE  (** Might be merged *)
  | `SHF_STRINGS  (** Contains nul-terminated strings *)
  | `SHF_INFO_LINK  (** `sh_info' contains SHT index *)
  | `SHF_LINK_ORDER  (** Preserve order after combining *)
  | `SHF_OS_NONCONFORMING  (** Non-standard OS specific handling required *)
  | `SHF_GROUP  (** Section is member of a group. *)
  | `SHF_TLS  (** Section hold thread-local data. *)
  | `SHF_COMPRESSED  (** Section with compressed data. *)
  | `SHF_MASKOS  (** OS-specific. *)
  | `SHF_MASKPROC  (** Processor-specific *)
  | `SHF_ORDERED  (** Special ordering requirement (Solaris). *)
  | `SHF_EXCLUDE
    (** Section is excluded unless referenced or allocated (Solaris). *) ]
(** Values for [section.sh_flags]. *)

type section = {
  sh_name : u32;  (** Section name as string table index *)
  sh_name_str : string;  (** Section name as resolved string *)
  sh_type : u32;  (** Section type (code, data, symbol table, etc.) *)
  sh_flags : u64;
      (** Section attributes (writable, executable, allocatable, etc.) *)
  sh_addr : u64;  (** Virtual address where section should be loaded *)
  sh_offset : u64;  (** File offset to section data *)
  sh_size : u64;  (** Section size in bytes *)
  sh_link : u32;  (** Index of associated section (type-dependent) *)
  sh_info : u32;  (** Additional section information (type-dependent) *)
  sh_addralign : u64;  (** Section alignment constraint *)
  sh_entsize : u64;  (** Size of entries if section contains a table *)
}
(** ELF section header describing a section within the file. Sections provide
    fine-grained organization of the file content for linking, debugging, and
    analysis. Each section has a specific type and set of attributes that
    determine how it should be processed. *)

type program_type =
  [ `PT_NULL  (** Program header table entry is unused. *)
  | `PT_LOAD
    (** Specifies a segment to load into memory at the given file address. *)
  | `PT_DYNAMIC  (** Dynamic linking information. *)
  | `PT_INTERP
    (** Specifies the location and size of the path to the dynamic linker. *)
  | `PT_NOTE
    (** The location and size of auxiliary information about the binary. *)
  | `PT_SHLIB  (** Reserved *)
  | `PT_PHDR  (** Location to load the program headers *)
  | `PT_TLS  (** Thread-local storage. *)
  | `PT_NUM  (** Number of defined types *)
  | `PT_LOOS  (** Start of OS-specific *)
  | `PT_GNU_EH_FRAME
    (** The stack unwinding information (points to the same memory as .eh_frame
        section). *)
  | `PT_GNU_STACK
    (** Indicates stack executability, specific to the Linux kernel *)
  | `PT_GNU_RELRO  (** Read-only after relocation. *)
  | `PT_GNU_PROPERTY
    (** Special note with dynamic linker specific information
        (.note.gnu.property) *)
  | `PT_GNU_SFRAME  (** SFrame segment. *)
  | `PT_LOSUNW
  | `PT_SUNWBSS  (** Sun Specific segment *)
  | `PT_SUNWSTACK  (** Stack segment *)
  | `PT_HISUNW
  | `PT_HIOS  (** End of OS-specific *)
  | `PT_LOPROC  (** Start of processor-specific *)
  | `PT_HIPROC  (** End of processor-specific *) ]
(** Legal values for [p_type] field of [program] (segment type).*)

(* Legal values for p_flags (segment flags).  *)
type program_flags =
  [ `PF_X  (** Segment is executable *)
  | `PF_W  (** Segment is writable *)
  | `PF_R  (** Segment is readable *)
  | `PF_RX  (** Segment is readable and executable *)
  | `PF_RW  (** Segment is readable and writable *)
  | `PF_WX  (** Segment is writable and executable *)
  | `PF_RWX  (** Segment is readable, writable and executable *)
  | `PF_MASKOS  (** OS-specific *)
  | `PF_MASKPROC  (** Processor-specific *) ]
(** ELF program segment permission flags. Defines access permissions for
    segments in memory during program execution. These flags control memory
    protection by specifying whether a segment can be read from, written to, or
    executed, enabling proper memory management and security. *)

type program = {
  p_type : program_type;  (** Segment type *)
  p_flags : program_flags;  (** Segment flags *)
  p_offset : u64;  (** Segment file offset *)
  p_vaddr : u64;  (** Segment virtual address *)
  p_paddr : u64;  (** Segment physical address *)
  p_filesz : u64;  (** Segment size in file *)
  p_memsz : u64;  (** Segment size in memory *)
  p_align : u64;  (** Segment alignment *)
}
(** Program headers describe the segments of the program relevant to program
    loading. *)

(** {2 What is the Auxiliary Vector?}

    The auxiliary vector (auxv) is a mechanism used by the Linux kernel and
    other Unix-like systems to pass system and program-specific information to
    user programs at startup. It consists of an array of key-value pairs
    containing essential data that programs and dynamic linkers need to function
    properly.

    {2 Purpose and Usage}

    The auxiliary vector serves several critical purposes:
    - Provides system information (page size, CPU features, security context)
    - Passes program metadata (entry point, program headers location)
    - Enables efficient dynamic linking without filesystem access
    - Allows secure communication of sensitive data (user/group IDs)
    - Supports performance optimizations by avoiding redundant system calls

    Common auxiliary vector entries include:
    - [AT_PAGESZ]: System memory page size (typically 4096 bytes)
    - [AT_PHDR]: Memory address where program headers are loaded
    - [AT_ENTRY]: Program entry point address
    - [AT_BASE]: Base address of the dynamic linker/interpreter
    - [AT_UID/AT_GID]: Real user and group IDs for security context

    {2 Memory Location}

    The auxiliary vector can be accessed from two sources:
    - Memory: Located on the program stack above environment variables during
      startup
    - Filesystem: Available via [/proc/<pid>/auxv] for any running process

    The exact memory location is platform-specific; consult the platform ELF ABI
    documents for details. See:
    https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf

    The auxiliary vector is essential for program interpreters and dynamic
    linkers (such as [/lib/ld-linux-x86-64.so.2]) to bootstrap the dynamic
    linking process without requiring additional system calls to examine
    executable files. *)

type entry_type =
  [ `AT_NULL  (** End of vector *)
  | `AT_IGNORE  (** Entry should be ignored *)
  | `AT_EXECFD  (** File descriptor of program *)
  | `AT_PHDR  (** Program headers for program *)
  | `AT_PHENT  (** Size of program header entry *)
  | `AT_PHNUM  (** Number of program headers *)
  | `AT_PAGESZ  (** System page size *)
  | `AT_BASE  (** Base address of interpreter *)
  | `AT_FLAGS  (** Flags *)
  | `AT_ENTRY  (** Entry point of program *)
  | `AT_NOTELF  (** Program is not ELF *)
  | `AT_UID  (** Real uid *)
  | `AT_EUID  (** Effective uid *)
  | `AT_GID  (** Real gid *)
  | `AT_EGID  (** Effective gid *)
  | `AT_CLKTCK  (** Frequency of times() *) ]
(** Auxiliary vector entry type identifiers. These constants define the
    different types of information that can be passed from the kernel to
    userspace programs through the auxiliary vector, including system
    parameters, program metadata, and security contexts. *)

type auxiliary_vector = {
  a_type : entry_type;
      (** Entry type identifying what information this entry contains *)
  a_val : u64;  (** Value associated with the entry type *)
}
(** Auxiliary vector entry containing system information passed from kernel to
    user programs at startup. Each entry consists of a type identifier and an
    associated value (address, size, flags, etc.). *)

val read_elf : Buffer.t -> header * section array
(** [read_elf buffer] decodes the header and section table from a buffer
    pointing to an ELF image. *)

(** {1 ELF Sections and Segments}

    ELF files organize their content using two overlapping but distinct
    structures: sections and segments. Understanding their relationship is
    crucial for working with ELF files effectively.

    {2 Sections vs Segments}

    {b Sections} are used during linking and debugging:
    - Fine-grained organization of data and code
    - Each section has a specific purpose (code, data, symbols, strings, etc.)
    - Defined by the Section Header Table
    - Used by linkers, debuggers, and analysis tools
    - Can be stripped from executables to reduce size

    {b Segments} are used during program loading:
    - Coarse-grained organization for runtime loading
    - Group related sections together for efficient loading
    - Defined by the Program Header Table
    - Used by the OS loader and dynamic linker
    - Essential for program execution (cannot be stripped)

    {2 Memory Layout Relationship}

    {v
    ELF File Structure:
    +------------------+
    |   ELF Header     |  <- Points to both header tables
    +------------------+
    |  Program Headers |  <- Segments (for loading)
    +------------------+
    |                  |
    |   File Content   |  <- Actual data/code
    |                  |
    +------------------+
    | Section Headers  |  <- Sections (for linking/debug)
    +------------------+

    Segment-to-Section Mapping:
    +----------------+     +------------------+
    |    LOAD        |---->| .text (code)     |
    |   Segment 1    |     | .rodata (const)  |
    +----------------+     +------------------+
    |    LOAD        |---->| .data (init var) |
    |   Segment 2    |     | .bss (uninit var)|
    +----------------+     +------------------+
    |   DYNAMIC      |---->| .dynamic         |
    +----------------+     +------------------+
    v}

    {2 Common Sections}

    - [.text]: Executable code
    - [.rodata]: Read-only data (string literals, constants)
    - [.data]: Initialized global and static variables
    - [.bss]: Uninitialized global and static variables
    - [.symtab]: Static symbol table (for debugging)
    - [.dynsym]: Dynamic symbol table (for runtime linking)
    - [.strtab/.dynstr]: String tables for symbol names
    - [.rel/.rela]: Relocation information
    - [.dynamic]: Dynamic linking information

    {2 Common Segments}

    - [LOAD]: Segments to be loaded into memory (typically .text, .data)
    - [DYNAMIC]: Dynamic linking information
    - [INTERP]: Path to program interpreter (dynamic linker)
    - [NOTE]: Auxiliary information (build ID, ABI notes)
    - [GNU_STACK]: Stack permissions and properties

    {2 Why Two Systems?}

    The dual organization serves different phases of a program's lifecycle:
    - {b Link time}: Sections provide fine-grained control for combining object
      files
    - {b Load time}: Segments provide efficient bulk loading with proper
      permissions
    - {b Debug time}: Sections provide detailed symbol and debugging information
    - {b Strip time}: Sections can be removed while preserving executable
      functionality *)

val read_programs : Buffer.t -> header -> program array
(** [read_programs buffer header] decodes the program headers from a buffer
    pointing to an ELF image. *)

val read_auxiliary_vector : Buffer.t -> auxiliary_vector list
(** [read_auxiliary_vector buffer] decodes the auxiliary vector from [buffer].
*)

(** {1 Standard ELF Symbol Tables}

    ELF files contain standardized symbol tables as defined by the ELF
    specification and System V Application Binary Interface (ABI):

    {2 Static Symbol Table (.symtab)}
    - Contains all symbols in the object file (local, global, debug information)
    - Used by debuggers, profilers, and development tools
    - Often stripped from release binaries to reduce file size
    - Uses {!val:read_symbol_table} with [~symtab_name:".symtab"]
    - Associated string table: [.strtab]

    {2 Dynamic Symbol Table (.dynsym)}
    - Contains only symbols needed for dynamic linking at runtime
    - Always present in dynamically linked executables and shared libraries
    - Smaller subset focused on runtime symbol resolution
    - Cannot be stripped as it's required for program execution
    - Uses {!val:read_symbol_table} with [~symtab_name:".dynsym"]
    - Associated string table: [.dynstr]

    {2 Usage Examples}
    {[
      (* Read default symbol table (tries .symtab first, falls back to .dynsym) *)
      let symbols = read_symbol_table buffer header sections

      (* Read static symbols explicitly *)
      let static_symbols =
        read_symbol_table ~symtab_name:".symtab" buffer header sections

      (* Read dynamic symbols explicitly *)
      let dynamic_symbols =
        read_symbol_table ~symtab_name:".dynsym" buffer header sections
    ]} *)

(** ELF symbol table entry *)

type symbol_binding =
  [ `STB_LOCAL  (** Local symbol *)
  | `STB_GLOBAL  (** Global symbol *)
  | `STB_WEAK  (** Weak symbol *)
  | `STB_LOOS  (** Start of OS-specific binding *)
  | `STB_HIOS  (** End of OS-specific binding *)
  | `STB_LOPROC  (** Start of processor-specific binding *)
  | `STB_HIPROC  (** End of processor-specific binding *)
  | `STB_UNKNOWN of int  (** Unknown binding *) ]
(** ELF symbol binding attributes. Defines the linkage visibility and behavior
    of symbols in the symbol table, controlling how symbols are resolved during
    linking. This determines whether symbols are local to the file, globally
    visible across modules, or have weak linkage semantics. *)

type symbol_type =
  [ `STT_NOTYPE  (** Symbol type is unspecified *)
  | `STT_OBJECT  (** Symbol is a data object *)
  | `STT_FUNC  (** Symbol is a code object *)
  | `STT_SECTION  (** Symbol associated with a section *)
  | `STT_FILE  (** Symbol's name is file name *)
  | `STT_COMMON  (** Symbol is a common data object *)
  | `STT_TLS  (** Symbol is thread-local data object *)
  | `STT_LOOS  (** Start of OS-specific symbol types *)
  | `STT_HIOS  (** End of OS-specific symbol types *)
  | `STT_LOPROC  (** Start of processor-specific symbol types *)
  | `STT_HIPROC  (** End of processor-specific symbol types *)
  | `STT_UNKNOWN of int  (** Unknown type *) ]
(** ELF symbol type classification. Categorizes symbols by their nature and
    intended use, distinguishing between data objects, functions, sections, and
    special symbol types. This classification helps linkers and debuggers
    understand how to process and resolve different kinds of symbols. *)

type symbol_visibility =
  [ `STV_DEFAULT  (** Default visibility *)
  | `STV_INTERNAL  (** Processor specific hidden class *)
  | `STV_HIDDEN  (** Symbol unavailable to other modules *)
  | `STV_PROTECTED  (** Not preemptible, not exported *)
  | `STV_UNKNOWN of int  (** Unknown visibility *) ]
(** ELF symbol visibility attributes. Controls the visibility and preemption
    behavior of symbols during dynamic linking. This determines how symbols are
    exposed to other modules and whether they can be intercepted or overridden
    by definitions in other shared libraries. *)

type symbol = {
  st_name : u32;  (** Symbol name string table index *)
  st_name_str : string;  (** Symbol name *)
  st_info : u8;  (** Symbol binding and type *)
  st_other : u8;  (** Symbol visibility *)
  st_shndx : u16;  (** Section index *)
  st_value : u64;  (** Symbol value *)
  st_size : u64;  (** Symbol size *)
  st_binding : symbol_binding;  (** Symbol binding *)
  st_type : symbol_type;  (** Symbol type *)
  st_visibility : symbol_visibility;  (** Symbol visibility *)
}
(** ELF symbol table entry. Represents a single symbol in the symbol table,
    containing all information needed to identify, locate, and link to the
    symbol. This includes both the raw ELF fields and parsed representations of
    binding, type, and visibility attributes. *)

val read_symbol_table :
  ?symtab_name:string -> Buffer.t -> header -> section array -> symbol array
(** [read_symbol_table ?symtab_name buffer header sections] reads symbol table
    from ELF file.

    @param symtab_name
      Optional symbol table section name to read from. Must be either ".symtab"
      (static symbol table) or ".dynsym" (dynamic symbol table). If not
      provided, defaults to trying ".symtab" first, then ".dynsym" as fallback.
      When ".dynsym" is specified, uses ".dynstr" as the string table; otherwise
      uses ".strtab".
    @param buffer The ELF file buffer
    @param header The ELF header
    @param sections Array of ELF sections
    @return Array of symbols from the specified or default symbol table
    @raise Failure
      if the specified symbol table or its corresponding string table is not
      found *)

val read_section_contents :
  Buffer.t -> section array -> string -> Buffer.t option
(** [read_section_contents buf section_name] reads the section contents for
    [section_name]. Returns None if the section name is not found *)

val get_section_contents : Buffer.t -> string -> Buffer.t option
(** [get_section_contents buffer section_name] searches for a section with the
    given [section_name] in the ELF file and returns its contents as a buffer.
    Returns [None] if the section is not found. *)
