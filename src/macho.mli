(** MacOS Mach-O parser based on /usr/include/mach-o/* headers *)

open Types

type magic =
  | MAGIC32
  | MAGIC64
  | CIGAM32
  | CIGAM64
      (** Magic numbers identifying the endianness and architecture of Mach-O
          files.
          - [MAGIC32]: 32-bit Mach-O file, native endianness
          - [MAGIC64]: 64-bit Mach-O file, native endianness
          - [CIGAM32]: 32-bit Mach-O file, swapped endianness
          - [CIGAM64]: 64-bit Mach-O file, swapped endianness *)

val string_of_magic : magic -> string
(** [string_of_magic magic] returns a human-readable string representation of
    the magic number for debugging and display purposes. *)

type unknown = [ `Unknown of int ]
(** Represents unknown or unrecognized values with their raw integer
    representation. *)

type cpu_type =
  [ `X86
  | `X86_64
  | `ARM
  | `ARM64
  | `ARM64_32
  | `POWERPC
  | `POWERPC64
  | unknown ]
(** CPU architectures supported by Mach-O binaries. Includes Intel x86/x64, ARM
    variants, PowerPC architectures, and a catch-all for unknown types. *)

type cpu_subtype =
  [ `Intel
  | `I386_ALL
  | `I386
  | `I486
  | `I486SX
  | `PENT
  | `PENTPRO
  | `PENTII_M3
  | `PENTII_M5
  | `CELERON
  | `CELERON_MOBILE
  | `PENTIUM_3
  | `PENTIUM_3_M
  | `PENTIUM_3_XEON
  | `PENTIUM_M
  | `PENTIUM_4
  | `PENTIUM_4_M
  | `ITANIUM
  | `ITANIUM_2
  | `XEON
  | `XEON_MP
  | `INTEL_FAMILY
  | `INTEL_FAMILY_MAX
  | `INTEL_MODEL
  | `INTEL_MODEL_ALL
  | `X86_ALL
  | `X86_64_ALL
  | `X86_ARCH1
  | `POWERPC_ALL
  | `POWERPC_601
  | `POWERPC_602
  | `POWERPC_603
  | `POWERPC_603e
  | `POWERPC_603ev
  | `POWERPC_604
  | `POWERPC_604e
  | `POWERPC_620
  | `POWERPC_750
  | `POWERPC_7400
  | `POWERPC_7450
  | `POWERPC_970
  | `ARM_ALL
  | `ARM_V4T
  | `ARM_V6
  | `ARM_V5TEJ
  | `ARM_XSCALE
  | `ARM_V7 (* ARMv7-A and ARMv7-R  *)
  | `ARM_V7F (* Cortex A9 *)
  | `ARM_V7S (* Swift *)
  | `ARM_V7K
  | `ARM_V8
  | unknown ]
(** CPU subtypes providing more specific processor identification within a CPU
    family. Includes various Intel processors, PowerPC variants, ARM versions,
    and unknown types. *)

type file_type =
  [ `OBJECT
  | `EXECUTE
  | `FVMLIB
  | `CORE
  | `PRELOAD
  | `DYLIB
  | `DYLINKER
  | `BUNDLE
  | `DYLIB_STUB
  | `DSYM
  | `KEXT_BUNDLE
  | `FILESET
  | `GPU_EXECUTE
  | `GPU_DYLIB
  | unknown ]
(** Types of Mach-O files, from relocatable object files to executables, dynamic
    libraries, bundles, and specialized types like GPU executables and file
    sets. *)

type header_flag =
  [ (*  the object file has no undefined references *)
    `NOUNDEFS
  | (*  the object file is the output of an incremental link against a base file and can't be link edited again *)
    `INCRLINK
  | (*  the object file is input for the dynamic linker and can't be staticly link edited again *)
    `DYLDLINK
  | (*  the object file's undefined references are bound by the dynamic linker when loaded. *)
    `BINDATLOAD
  | (*  the file has its dynamic undefined references prebound. *)
    `PREBOUND
  | (*  the file has its read-only and read-write segments split *)
    `SPLIT_SEGS
  | (*  the image is using two-level name space bindings *)
    `TWOLEVEL
  | (*  the executable is forcing all images to use flat name space bindings *)
    `FORCE_FLAT
  | (*  this umbrella guarantees no multiple defintions of symbols in its sub-images so the two-level namespace hints can always be used. *)
    `NOMULTIDEFS
  | (*  do not have dyld notify the prebinding agent about this executable *)
    `NOFIXPREBINDING
  | (*  the binary is not prebound but can have its prebinding redone. only used when `PREBOUND is not set. *)
    `PREBINDABLE
  | (*  indicates that this binary binds to all two-level namespace modules of its dependent libraries. only used when `PREBINDABLE and `TWOLEVEL are both set. *)
    `ALLMODSBOUND
  | (*  safe to divide up the sections into sub-sections via symbols for dead code stripping *)
    `SUBSECTIONS_VIA_SYMBOLS
  | (*  the binary has been canonicalized via the unprebind operation *)
    `CANONICAL
  | (*  the final linked image contains external weak symbols *)
    `WEAK_DEFINES
  | (*  the final linked image uses weak symbols *)
    `BINDS_TO_WEAK
  | (*  When this bit is set, all stacks  in the task will be given stack execution privilege.  Only used in `EXECUTE filetypes. *)
    `ALLOW_STACK_EXECUTION
  | (*  When this bit is set, the binary  declares it is safe for use in processes with uid zero *)
    `ROOT_SAFE
  | (*  When this bit is set, the binary  declares it is safe for use in processes when issetugid() is true *)
    `SETUID_SAFE
  | (*  When this bit is set on a dylib,  the static linker does not need to examine dependent dylibs to see if any are re-exported *)
    `NO_REEXPORTED_DYLIBS
  | (*  When this bit is set, the OS will load the main executable at a random address.  Only used in `EXECUTE filetypes. *)
    `PIE ]
(** Flags in the Mach-O header indicating various linking and loading behaviors,
    such as undefined references, dynamic linking, prebinding, and security
    features. *)

type header = {
  magic : magic;
  cpu_type : cpu_type;
  cpu_subtype : cpu_subtype;
  file_type : file_type;
  flags : header_flag list;
}
(** The Mach-O header containing essential information about the binary
    including endianness, architecture, file type, and various flags controlling
    linking behavior. *)

type reloc_type =
  [ `GENERIC_RELOC_VANILLA
  | `GENERIC_RELOC_PAIR
  | `GENERIC_RELOC_SECTDIFF
  | `GENERIC_RELOC_LOCAL_SECTDIFF
  | `GENERIC_RELOC_PB_LA_PTR
  | `X86_64_RELOC_BRANCH
  | `X86_64_RELOC_GOT_LOAD
  | `X86_64_RELOC_GOT
  | `X86_64_RELOC_SIGNED
  | `X86_64_RELOC_UNSIGNED
  | `X86_64_RELOC_SUBTRACTOR
  | `X86_64_RELOC_SIGNED_1
  | `X86_64_RELOC_SIGNED_2
  | `X86_64_RELOC_SIGNED_4
  | `PPC_RELOC_VANILLA
  | `PPC_RELOC_PAIR
  | `PPC_RELOC_BR14
  | `PPC_RELOC_BR24
  | `PPC_RELOC_HI16
  | `PPC_RELOC_LO16
  | `PPC_RELOC_HA16
  | `PPC_RELOC_LO14
  | `PPC_RELOC_SECTDIFF
  | `PPC_RELOC_LOCAL_SECTDIFF
  | `PPC_RELOC_PB_LA_PTR
  | `PPC_RELOC_HI16_SECTDIFF
  | `PPC_RELOC_LO16_SECTDIFF
  | `PPC_RELOC_HA16_SECTDIFF
  | `PPC_RELOC_JBSR
  | `PPC_RELOC_LO14_SECTDIFF
  | unknown ]
(** Relocation types for different architectures (generic, x86-64, PowerPC)
    indicating how addresses should be modified during linking and loading. *)

type relocation_info = {
  ri_address : int;
      (** Offset from start of section to place to be relocated *)
  ri_symbolnum : u32;  (** Index into symbol or section table *)
  ri_pcrel : bool;
      (** Indicates if the item to be relocated is part of an instruction
          containing PC-relative addressing *)
  ri_length : u32;
      (** Length of item containing address to be relocated (literal form (4)
          instead of power of two (2)) *)
  ri_extern : bool;
      (** Indicates whether symbolnum is an index into the symbol table (true)
          or section table (false) *)
  ri_type : reloc_type;  (** Relocation type *)
}
(** Information needed to relocate addresses during linking. Contains the
    location to be relocated, the symbol or section it references, and how the
    relocation should be performed. *)

type scattered_relocation_info = {
  rs_pcrel : bool;
      (** Indicates if the item to be relocated is part of an instruction
          containing PC-relative addressing *)
  rs_length : u32;
      (** Length of item containing address to be relocated (literal form (4)
          instead of power of two (2)) *)
  rs_type : reloc_type;  (** Relocation type *)
  rs_address : u32;
      (** Offset from start of section to place to be relocated *)
  rs_value : s32;
      (** Address of the relocatable expression for the item in the file that
          needs to be updated if the address is changed *)
}
(** Scattered relocation information used when the relocation cannot be
    described by a simple symbol or section reference. Contains the actual
    address value and relocation details. *)

type relocation =
  [ `Relocation_info of relocation_info
  | `Scattered_relocation_info of scattered_relocation_info ]
(** Union type representing either a standard or scattered relocation entry.
    Standard relocations reference symbols or sections by index, while scattered
    relocations contain literal addresses. *)

type sec_type =
  [ `S_REGULAR  (** Regular section *)
  | `S_ZEROFILL  (** Zero fill on demand section *)
  | `S_CSTRING_LITERALS  (** Section with only literal C strings *)
  | `S_4BYTE_LITERALS  (** Section with only 4 byte literals *)
  | `S_8BYTE_LITERALS  (** Section with only 8 byte literals *)
  | `S_LITERAL_POINTERS  (** Section with only pointers to literals *)
  | `S_NON_LAZY_SYMBOL_POINTERS
    (** Section with only non-lazy symbol pointers *)
  | `S_LAZY_SYMBOL_POINTERS  (** Section with only lazy symbol pointers *)
  | `S_SYMBOL_STUBS
    (** Section with only symbol stubs, byte size of stub in the reserved2 field
    *)
  | `S_MOD_INIT_FUNC_POINTERS
    (** Section with only function pointers for initialization *)
  | `S_MOD_TERM_FUNC_POINTERS
    (** Section with only function pointers for termination *)
  | `S_COALESCED  (** Section contains symbols that are to be coalesced *)
  | `S_GB_ZEROFILL
    (** Zero fill on demand section (that can be larger than 4 gigabytes) *)
  | `S_INTERPOSING
    (** Section with only pairs of function pointers for interposing *)
  | `S_16BYTE_LITERALS  (** Section with only 16 byte literals *)
  | `S_DTRACE_DOF  (** Section contains DTrace Object Format *)
  | `S_LAZY_DYLIB_SYMBOL_POINTERS
    (** Section with only lazy symbol pointers to lazy loaded dylibs *)
  | unknown ]
(** Section types indicating the content and purpose of a section within a
    segment. Each type defines how the section data should be interpreted and
    used by the linker and loader. *)

type sec_user_attr =
  [ `PURE_INSTRUCTIONS  (** Section contains only true machine instructions *)
  | `NO_TOC
    (** Section contains coalesced symbols that are not to be in a ranlib table
        of contents *)
  | `STRIP_STATIC_SYMS
    (** OK to strip static symbols in this section in files with the MH_DYLDLINK
        flag *)
  | `NO_DEAD_STRIP  (** No dead stripping *)
  | `LIVE_SUPPORT  (** Blocks are live if they reference live blocks *)
  | `SELF_MODIFYING_CODE  (** Used with i386 code stubs written on by dyld *)
  | `DEBUG  (** A debug section *) ]
(** User-defined section attributes controlling how sections are treated during
    linking and optimization processes. *)

type sec_sys_attr =
  [ `SOME_INSTRUCTIONS  (** Section contains some machine instructions *)
  | `EXT_RELOC  (** Section has external relocation entries *)
  | `LOC_RELOC  (** Section has local relocation entries *) ]
(** System-defined section attributes indicating relocation and instruction
    content. *)

type section = {
  sec_sectname : string;  (** Name of section *)
  sec_segname : string;  (** Name of segment that should own this section *)
  sec_addr : u64;  (** Virtual memory address for section *)
  sec_size : u64;  (** Size of section *)
  sec_offset : u32;  (** File offset of section *)
  sec_align : int;
      (** Alignment required by section (literal form, not power of two, e.g. 8
          not 3) *)
  sec_relocs : relocation array;  (** Relocations for this section *)
  sec_type : sec_type;  (** Type of section *)
  sec_user_attrs : sec_user_attr list;  (** User attributes of section *)
  sec_sys_attrs : sec_sys_attr list;  (** System attributes of section *)
}
(** A section within a segment, containing code or data with specific attributes
    and relocations. Sections are the finest granularity of organization within
    Mach-O files. *)

type vm_prot = [ `READ | `WRITE | `EXECUTE ]
(** Virtual memory protection flags controlling access permissions for segments
    and sections. *)

type seg_flag =
  [ `HIGHVM
    (* The file contents for this segment is for the high part of the VM space, the low part is zero filled (for stacks in core files). *)
  | `NORELOC
    (* This segment has nothing that was relocated in it and nothing relocated to it, that is it may be safely replaced without relocation. *)
  ]
(** Segment flags controlling special handling of segment contents and
    relocations. *)

type segment = {
  seg_segname : string;  (** Segment name *)
  seg_vmaddr : u64;  (** Virtual address where the segment is loaded *)
  seg_vmsize : u64;  (** Size of segment at runtime *)
  seg_fileoff : u64;  (** File offset of the segment *)
  seg_filesize : u64;  (** Size of segment in file *)
  seg_maxprot : vm_prot list;  (** Maximum virtual memory protection *)
  seg_initprot : vm_prot list;  (** Initial virtual memory protection *)
  seg_flags : seg_flag list;  (** Segment flags *)
  seg_sections : section array;  (** Sections owned by this segment *)
}
(** A segment containing one or more sections, representing a contiguous range
    of virtual memory that is mapped from the file during loading. Segments
    define memory protection and layout. *)

type sym_type =
  [ (* undefined symbol, n_sect is 0 *)
    `UNDF
  | (* absolute symbol, does not need relocation, n_sect is 0 *)
    `ABS
  | (* symbol is defined in section n_sect *)
    `SECT
  | (* symbol is undefined and the image is using a prebound value for the symbol, n_sect is 0 *)
    `PBUD
  | (* symbol is defined to be the same as another symbol. n_value is a string table offset indicating the name of that symbol *)
    `INDR
  | (* stab global symbol: name,,0,type,0 *)
    `GSYM
  | (* stab procedure name (f77 kludge): name,,0,0,0 *)
    `FNAME
  | (* stab procedure: name,,n_sect,linenumber,address *)
    `FUN
  | (* stab static symbol: name,,n_sect,type,address *)
    `STSYM
  | (* stab .lcomm symbol: name,,n_sect,type,address *)
    `LCSYM
  | (* stab begin nsect sym: 0,,n_sect,0,address *)
    `BNSYM
  | (* stab emitted with gcc2_compiled and in gcc source *)
    `OPT
  | (* stab register sym: name,,0,type,register *)
    `RSYM
  | (* stab src line: 0,,n_sect,linenumber,address *)
    `SLINE
  | (* stab end nsect sym: 0,,n_sect,0,address *)
    `ENSYM
  | (* stab structure elt: name,,0,type,struct_offset *)
    `SSYM
  | (* stab source file name: name,,n_sect,0,address *)
    `SO
  | (* stab object file name: name,,0,0,st_mtime *)
    `OSO
  | (* stab local sym: name,,0,type,offset *)
    `LSYM
  | (* stab include file beginning: name,,0,0,sum *)
    `BINCL
  | (* stab #included file name: name,,n_sect,0,address *)
    `SOL
  | (* stab compiler parameters: name,,0,0,0 *)
    `PARAMS
  | (* stab compiler version: name,,0,0,0 *)
    `VERSION
  | (* stab compiler -O level: name,,0,0,0 *)
    `OLEVEL
  | (* stab parameter: name,,0,type,offset *)
    `PSYM
  | (* stab include file end: name,,0,0,0 *)
    `EINCL
  | (* stab alternate entry: name,,n_sect,linenumber,address *)
    `ENTRY
  | (* stab left bracket: 0,,0,nesting level,address *)
    `LBRAC
  | (* stab deleted include file: name,,0,0,sum *)
    `EXCL
  | (* stab right bracket: 0,,0,nesting level,address *)
    `RBRAC
  | (* stab begin common: name,,0,0,0 *)
    `BCOMM
  | (* stab end common: name,,n_sect,0,0 *)
    `ECOMM
  | (* stab end common (local name): 0,,n_sect,0,address *)
    `ECOML
  | (* stab second stab entry with length information *)
    `LENG
  | (* stab global pascal symbol: name,,0,subtype,line *)
    `PC
  | unknown ]
(** Symbol types including regular symbols (UNDF, ABS, SECT) and STAB debug
    symbols. STAB symbols provide debugging information like source file names,
    line numbers, and local variable information used by debuggers. *)

type reference_flag =
  [ (* reference to an external non-lazy symbol *)
    `UNDEFINED_NON_LAZY
  | (* reference to an external lazy symbol *)
    `UNDEFINED_LAZY
  | (* symbol is defined in this module *)
    `DEFINED
  | (* symbol is defined in this module and visible only to modules within this shared library *)
    `PRIVATE_DEFINED
  | (* reference to an external non-lazy symbol and visible only to modules within this shared library *)
    `PRIVATE_UNDEFINED_NON_LAZY
  | (* reference to an external lazy symbol and visible only to modules within this shared library *)
    `PRIVATE_UNDEFINED_LAZY
  | (* set for all symbols referenced by dynamic loader APIs *)
    `REFERENCED_DYNAMICALLY
  | (* indicates the symbol is a weak reference, set to 0 if definition cannot be found *)
    `SYM_WEAK_REF
  | (* indicates the symbol is a weak definition, will be overridden by a strong definition at link-time *)
    `SYM_WEAK_DEF
  | (* for two-level mach-o objects, specifies the index of the library in which this symbol is defined. zero specifies current image. *)
    `LIBRARY_ORDINAL of u16
  | unknown ]
(** Reference flags indicating how symbols are bound and resolved during
    linking. Controls symbol visibility, weak binding, and library ordinals for
    two-level namespaces. *)

type symbol = {
  sym_name : string;  (** Symbol name *)
  sym_type : sym_type;  (** Symbol type *)
  sym_pext : bool;  (** True if limited global scope *)
  sym_ext : bool;  (** True if external symbol *)
  sym_sect : u8;  (** Section index where the symbol can be found *)
  sym_flags : [ `Uninterpreted of u16 | `Flags of reference_flag list ];
      (** For stab entries, uninterpreted flags field; otherwise reference flags
      *)
  sym_value : u64;
      (** Symbol value, 32-bit symbol values are promoted to 64-bit for
          simplicity *)
}
(** A symbol table entry representing a named location in code or data. Symbols
    can be functions, variables, or debugging information, and may reference
    external libraries. *)

type dylib_module = {
  dylib_module_name_offset : u32;  (** Module name string table offset *)
  dylib_ext_def_sym : u32 * u32;
      (** (initial, count) pair of symbol table indices for externally defined
          symbols *)
  dylib_ref_sym : u32 * u32;
      (** (initial, count) pair of symbol table indices for referenced symbols
      *)
  dylib_local_sym : u32 * u32;
      (** (initial, count) pair of symbol table indices for local symbols *)
  dylib_ext_rel : u32 * u32;
      (** (initial, count) pair of symbol table indices for externally
          referenced symbols *)
  dylib_init : u32 * u32;
      (** (initial, count) pair of symbol table indices for the index of the
          module init section and the number of init pointers *)
  dylib_term : u32 * u32;
      (** (initial, count) pair of symbol table indices for the index of the
          module term section and the number of term pointers *)
  dylib_objc_module_info_addr : u32;
      (** Statically linked address of the start of the data for this module in
          the __module_info section in the __OBJC segment *)
  dylib_objc_module_info_size : u64;
      (** Number of bytes of data for this module that are used in the
          __module_info section in the __OBJC segment *)
}
(** Module information for dynamic libraries, containing indices into various
    symbol tables and initialization/termination routines. *)

type toc_entry = {
  symbol_index : u32;  (** Index into symbol table *)
  module_index : u32;  (** Index into module table *)
}
(** Table of contents entry mapping symbols to their defining modules. *)

type dynamic_symbol_table = {
  local_syms : u32 * u32;  (** Symbol table index and count for local symbols *)
  ext_def_syms : u32 * u32;
      (** Symbol table index and count for externally defined symbols *)
  undef_syms : u32 * u32;
      (** Symbol table index and count for undefined symbols *)
  toc_entries : toc_entry array;
      (** List of symbol index and module index pairs *)
  modules : dylib_module array;  (** Modules *)
  ext_ref_syms : u32 array;  (** List of external reference symbol indices *)
  indirect_syms : u32 array;  (** List of indirect symbol indices *)
  ext_rels : relocation array;  (** External relocations *)
  loc_rels : relocation array;  (** Local relocations *)
}
(** Dynamic symbol table containing information needed for dynamic linking,
    including symbol organization and relocation data. *)

type dylib = {
  dylib_name : string;  (** Name of the dynamic library *)
  dylib_timestamp : u32;  (** Time when the library was built *)
  dylib_current_version : u32;  (** Current version of the library *)
  dylib_compatibility_version : u32;
      (** Oldest version this library is compatible with *)
}
(** Dynamic library information including name and version details. *)

(** Load commands instruct the dynamic linker how to set up the process from the
    Mach-O file. Commands specify segments to load, libraries to link, symbols
    to resolve, and other setup tasks. Each command contains specific data
    relevant to its operation. *)
type command =
  (* segment of this file to be mapped *)
  | LC_SEGMENT_32 of segment lazy_t
  (* static link-edit symbol table and stab info *)
  | LC_SYMTAB of (symbol array * Buffer.t) lazy_t
  (* thread state information (list of (flavor, [long]) pairs) *)
  | LC_THREAD of (u32 * u32 array) list lazy_t
  (* unix thread state information (includes a stack) (list of (flavor, [long] pairs) *)
  | LC_UNIXTHREAD of (u32 * u32 array) list lazy_t
  (* dynamic link-edit symbol table info *)
  | LC_DYSYMTAB of dynamic_symbol_table lazy_t
  (* load a dynamically linked shared library (name, timestamp, current version, compatibility version) *)
  | LC_LOAD_DYLIB of dylib lazy_t
  (* dynamically linked shared lib ident (name, timestamp, current version, compatibility version) *)
  | LC_ID_DYLIB of dylib lazy_t
  (* load a dynamic linker (name of dynamic linker) *)
  | LC_LOAD_DYLINKER of string
  (* dynamic linker identification (name of dynamic linker) *)
  | LC_ID_DYLINKER of string
  (* modules prebound for a dynamically linked shared library (name, list of module indices) *)
  | LC_PREBOUND_DYLIB of (string * u8 array) lazy_t
  (* image routines (virtual address of initialization routine, module index where it resides) *)
  | LC_ROUTINES_32 of u32 * u32
  (* sub framework (name) *)
  | LC_SUB_FRAMEWORK of string
  (* sub umbrella (name) *)
  | LC_SUB_UMBRELLA of string
  (* sub client (name) *)
  | LC_SUB_CLIENT of string
  (* sub library (name) *)
  | LC_SUB_LIBRARY of string
  (* two-level namespace lookup hints (list of (subimage index, symbol table index) pairs *)
  | LC_TWOLEVEL_HINTS of (u32 * u32) array lazy_t
  (* prebind checksum (checksum) *)
  | LC_PREBIND_CKSUM of u32
  (* load a dynamically linked shared library that is allowed to be missing (symbols are weak imported) (name, timestamp, current version, compatibility version) *)
  | LC_LOAD_WEAK_DYLIB of dylib lazy_t
  (* 64-bit segment of this file to mapped *)
  | LC_SEGMENT_64 of segment lazy_t
  (* 64-bit image routines (virtual address of initialization routine, module index where it resides) *)
  | LC_ROUTINES_64 of u64 * u64
  (* the uuid for an image or its corresponding dsym file (8 element list of bytes) *)
  | LC_UUID of string
  (* runpath additions (path) *)
  | LC_RPATH of string
  (* local of code signature *)
  | LC_CODE_SIGNATURE of u32 * u32
  (* local of info to split segments *)
  | LC_SEGMENT_SPLIT_INFO of u32 * u32
  | LC_UNHANDLED of int * Buffer.t

val read_symbol_table :
  header -> Buffer.t -> Buffer.cursor -> symbol array * Buffer.t
(** [read_symbol_table header buffer cursor] reads the symbol table from a
    Mach-O LC_SYMTAB load command. Returns an array of symbols and the string
    table buffer. The cursor should be positioned at the start of the symbol
    table command data (after the standard load command header).

    @param header The Mach-O header containing architecture information
    @param buffer The complete Mach-O file buffer
    @param cursor Buffer cursor positioned at symbol table command data
    @return Tuple of (symbol array, string table buffer) *)

val read_load_command : header -> Buffer.t -> Buffer.cursor -> command
(** [read_load_command header buffer cursor] reads a single load command from
    the Mach-O file. The cursor should be positioned at the start of a load
    command (at the cmd field).

    @param header The Mach-O header containing architecture information
    @param buffer The complete Mach-O file buffer
    @param cursor Buffer cursor positioned at load command start
    @return The parsed load command structure *)

val read_load_commands : header -> Buffer.t -> Buffer.cursor -> command list
(** [read_load_commands header buffer cursor] reads all remaining load commands
    from the current cursor position until the end of the load commands region.

    @param header The Mach-O header containing architecture information
    @param buffer The complete Mach-O file buffer
    @param cursor Buffer cursor positioned at start of load commands
    @return List of all parsed load command structures *)

val read : Buffer.t -> header * command list
(** [read] decodes the [header] and load [command] list, from a [Buffer.t]
    pointing to a MachO image *)

val section_body : Buffer.t -> section -> Buffer.t
(** [section_body macho section] returns a sub-buffer with the contents of the
    [section] of the MachO image in [Buffer.t]. *)
