open Types

(** Windows PE/COFF parser based on
    {:https://docs.microsoft.com/en-us/windows/win32/debug/pe-format}.

    {1 Overview}

    PE (Portable Executable) and COFF (Common Object File Format) are
    Microsoft's standard binary file formats for Windows executables, object
    files, and DLLs. This module provides parsing capabilities for both formats.

    {2 What are PE/COFF Files?}

    {b COFF (Common Object File Format)}:
    - Object file format for intermediate compilation results
    - Contains relocatable code and data sections
    - Used by linkers to create final executables
    - Originally developed by AT&T for Unix System V
    - Adopted and extended by Microsoft for Windows

    {b PE (Portable Executable)}:
    - Executable file format based on COFF
    - Used for .exe, .dll, .sys, and other executable files on Windows
    - Extends COFF with additional Windows-specific headers and structures
    - Supports both 32-bit (PE32) and 64-bit (PE32+) architectures
    - Contains runtime loading and dynamic linking information

    {2 File Structure}

    PE files have a layered structure that builds upon the COFF foundation:

    {v
    PE File Layout:
    +---------------------------+
    |      DOS Header           |  <- Legacy 16-bit DOS compatibility
    |      ("MZ" signature)     |
    +---------------------------+
    |      DOS Stub Program     |  <- Optional 16-bit code
    +---------------------------+
    |      PE Signature         |  <- "PE\0\0" magic number
    +---------------------------+
    |      COFF Header          |  <- Core file metadata (20 bytes)
    +---------------------------+
    |      Optional Header      |  <- PE-specific information
    |      (PE32: 224 bytes)    |     - Entry point, image base
    |      (PE32+: 240 bytes)   |     - Subsystem, DLL characteristics
    +---------------------------+
    |      Section Headers      |  <- Array of section metadata
    |      (40 bytes each)      |
    +---------------------------+
    |                           |
    |      Section Data         |  <- Actual code and data
    |      (.text, .data, etc.) |
    |                           |
    +---------------------------+
    v}

    {2 Key Components}

    {b DOS Header}: Legacy compatibility header allowing PE files to run on DOS
    systems (displaying "This program cannot be run in DOS mode" message).

    {b COFF Header}: Core 20-byte structure containing:
    - Target machine architecture (x86, x64, ARM, etc.)
    - Number of sections in the file
    - File creation timestamp
    - Symbol table information
    - File characteristics flags

    {b Optional Header}: PE-specific extended header (despite the name, always
    present in PE files) containing:
    - Entry point address for program execution
    - Image base address for memory loading
    - Section and file alignment requirements
    - Subsystem type (console, GUI, driver, etc.)
    - DLL characteristics and stack/heap sizes

    {b Section Headers}: Array of 40-byte structures describing each section:
    - Section name (up to 8 characters)
    - Virtual and file addresses/sizes
    - Section characteristics (readable, writable, executable)
    - Relocation and line number information

    {2 Common Sections}

    - {b .text}: Executable code section
    - Characteristics: [CNT_CODE; MEM_EXECUTE; MEM_READ]
    - {b .data}: Initialized global and static variables
    - Characteristics: [CNT_INITIALIZED_DATA; MEM_READ; MEM_WRITE]
    - {b .rdata}: Read-only data (constants, string literals)
    - Characteristics: [CNT_INITIALIZED_DATA; MEM_READ]
    - {b .bss}: Uninitialized data (zero-filled at load time)
    - Characteristics: [CNT_UNINITIALIZED_DATA; MEM_READ; MEM_WRITE]
    - {b .idata}: Import address table for DLL functions
    - Characteristics: [CNT_INITIALIZED_DATA; MEM_READ; MEM_WRITE]
    - {b .edata}: Export table for DLL-exported functions
    - Characteristics: [CNT_INITIALIZED_DATA; MEM_READ]
    - {b .rsrc}: Embedded resources (icons, dialogs, version info)
    - Characteristics: [CNT_INITIALIZED_DATA; MEM_READ]
    - {b .reloc}: Base relocation table for ASLR support
    - Characteristics: [CNT_INITIALIZED_DATA; MEM_READ; MEM_DISCARDABLE]
    - {b .debug_*}: Debug information sections
    - Characteristics: [LNK_INFO; LNK_REMOVE; MEM_DISCARDABLE]

    {3 Section Characteristics Details}

    The PE format defines comprehensive section characteristics that control
    linking, loading, and runtime behavior:

    {b Content Classification}:
    - [TYPE_NO_PAD]: Section should not be padded to alignment boundary
    - [CNT_CODE]: Contains executable machine code
    - [CNT_INITIALIZED_DATA]: Contains initialized data (variables, constants)
    - [CNT_UNINITIALIZED_DATA]: Contains uninitialized data (BSS segment)

    {b Linker Control}:
    - [LNK_INFO]: Informational section (comments, debug info)
    - [LNK_REMOVE]: Section excluded from final executable image
    - [LNK_COMDAT]: COMDAT section for template instantiation/deduplication

    {b Memory Management}:
    - [MEM_EXECUTE]: Section can be executed (code pages)
    - [MEM_READ]: Section can be read (most sections)
    - [MEM_WRITE]: Section can be written to (data sections)
    - [MEM_SHARED]: Section shared between processes (system sections)
    - [MEM_DISCARDABLE]: Section can be discarded after loading (debug info)
    - [MEM_NOT_CACHED]: Disable caching (device drivers, memory-mapped I/O)
    - [MEM_NOT_PAGED]: Keep in physical memory (kernel code, interrupt handlers)

    {2 PE32 vs PE32+}

    The format supports both 32-bit and 64-bit architectures:

    - {b PE32}: 32-bit format with 32-bit addresses and pointers
    - {b PE32+}: 64-bit format with 64-bit addresses and some expanded fields
    - Detected by the magic number in the optional header (0x10B vs 0x20B)
    - Some fields change size between formats (image base, stack/heap sizes)

    {2 Usage Examples}

    {[
      (* Detect if a buffer contains a PE file *)
      if Pe.is_pe buffer then
        Printf.printf "Found PE file\n"

      (* Parse complete PE structure *)
      let pe_obj = Pe.read buffer in

      (* Get basic information *)
      let arch = Pe.get_architecture pe_obj in
      let is_64 = Pe.is_64bit pe_obj in
      let is_exe = Pe.is_executable pe_obj in

      (* Access sections *)
      let sections = Pe.sections pe_obj in
      Array.iter (fun sec ->
        Printf.printf "Section: %s\n" sec.name
      ) sections
    ]}

    {2 References}

    - {{:https://docs.microsoft.com/en-us/windows/win32/debug/pe-format}
       Microsoft PE/COFF Specification}
    - {{:https://github.com/ocaml/flexdll/blob/master/coff.ml} FlexDLL COFF
       Implementation}
    - {{:https://github.com/ocaml/ocaml/blob/trunk/utils/binutils.ml} OCaml
       Binutils PE Support} *)

type machine_type =
  [ `IMAGE_FILE_MACHINE_I386  (** Intel 386 or later processors *)
  | `IMAGE_FILE_MACHINE_AMD64  (** AMD64/x64 architecture *)
  | `IMAGE_FILE_MACHINE_ARM  (** ARM little-endian *)
  | `IMAGE_FILE_MACHINE_ARM64  (** ARM64 little-endian *)
  | `IMAGE_FILE_MACHINE_UNKNOWN of u16
    (** Unknown machine type with raw value *) ]
(** Machine architecture types supported by PE/COFF format *)

(** PE format magic numbers indicating 32-bit vs 64-bit PE files *)
type pe_magic =
  | PE32  (** 32-bit PE format (0x10B) *)
  | PE32PLUS  (** 64-bit PE format (0x20B) *)

type section_characteristics =
  [ `IMAGE_SCN_TYPE_NO_PAD  (** Section should not be padded to next boundary *)
  | `IMAGE_SCN_CNT_CODE  (** Section contains executable code *)
  | `IMAGE_SCN_CNT_INITIALIZED_DATA  (** Section contains initialized data *)
  | `IMAGE_SCN_CNT_UNINITIALIZED_DATA
    (** Section contains uninitialized data *)
  | `IMAGE_SCN_LNK_INFO  (** Section contains comments or other information *)
  | `IMAGE_SCN_LNK_REMOVE  (** Section will not become part of the image *)
  | `IMAGE_SCN_LNK_COMDAT  (** Section contains COMDAT data *)
  | `IMAGE_SCN_MEM_DISCARDABLE  (** Section can be discarded as needed *)
  | `IMAGE_SCN_MEM_NOT_CACHED  (** Section cannot be cached *)
  | `IMAGE_SCN_MEM_NOT_PAGED  (** Section is not pageable *)
  | `IMAGE_SCN_MEM_SHARED  (** Section can be shared in memory *)
  | `IMAGE_SCN_MEM_EXECUTE  (** Section can be executed as code *)
  | `IMAGE_SCN_MEM_READ  (** Section can be read *)
  | `IMAGE_SCN_MEM_WRITE  (** Section can be written to *)
  | `IMAGE_SCN_UNKNOWN of u32  (** Unknown characteristics with raw flags *) ]
(** Section characteristics flags indicating section properties and behavior.

    These flags control how sections are processed during linking and loading:

    {b Content Type Flags}:
    - Content classification flags indicate the nature of section data
    - Used by linkers to group related sections and set appropriate permissions

    {b Linker Flags}:
    - Control linker behavior for object files and debugging information
    - Determine whether sections are included in the final executable image

    {b Memory Management Flags}:
    - Control runtime memory behavior and access permissions
    - Set by the loader to configure memory protection and caching behavior

    Common flag combinations:
    - Executable code: [CNT_CODE; MEM_EXECUTE; MEM_READ]
    - Read-only data: [CNT_INITIALIZED_DATA; MEM_READ]
    - Read-write data: [CNT_INITIALIZED_DATA; MEM_READ; MEM_WRITE]
    - Debug info: [LNK_INFO; LNK_REMOVE; MEM_DISCARDABLE] *)

type coff_header = {
  machine : machine_type;  (** Target machine architecture *)
  number_of_sections : u16;  (** Number of section headers *)
  time_date_stamp : u32;  (** File creation timestamp *)
  pointer_to_symbol_table : u32;  (** File offset to symbol table *)
  number_of_symbols : u32;  (** Number of symbol table entries *)
  size_of_optional_header : u16;  (** Size of optional header *)
  characteristics : u16;  (** File characteristics flags *)
}
(** COFF file header structure (20 bytes) *)

(** Data directory types as defined in the PE specification *)
type data_directory_type =
  [ `IMAGE_DIRECTORY_ENTRY_EXPORT  (** Export table *)
  | `IMAGE_DIRECTORY_ENTRY_IMPORT  (** Import table *)
  | `IMAGE_DIRECTORY_ENTRY_RESOURCE  (** Resource table *)
  | `IMAGE_DIRECTORY_ENTRY_EXCEPTION  (** Exception table *)
  | `IMAGE_DIRECTORY_ENTRY_SECURITY  (** Certificate table *)
  | `IMAGE_DIRECTORY_ENTRY_BASERELOC  (** Base relocation table *)
  | `IMAGE_DIRECTORY_ENTRY_DEBUG  (** Debug data *)
  | `IMAGE_DIRECTORY_ENTRY_ARCHITECTURE  (** Architecture specific data *)
  | `IMAGE_DIRECTORY_ENTRY_GLOBALPTR  (** Global pointer register *)
  | `IMAGE_DIRECTORY_ENTRY_TLS  (** Thread local storage table *)
  | `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG  (** Load configuration table *)
  | `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  (** Bound import table *)
  | `IMAGE_DIRECTORY_ENTRY_IAT  (** Import address table *)
  | `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT  (** Delay import descriptor *)
  | `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR  (** COM+ runtime descriptor *)
  | `IMAGE_DIRECTORY_ENTRY_RESERVED  (** Reserved *)
  ]

(** Data directory entry containing address and size of a table *)
and data_directory_entry = {
  virtual_address : u32;  (** RVA of the table *)
  size : u32;  (** Size of the table in bytes *)
}

(** Data directory containing all Windows-specific tables *)
and data_directory = {
  export_table : data_directory_entry option;  (** Export table *)
  import_table : data_directory_entry option;  (** Import table *)
  resource_table : data_directory_entry option;  (** Resource table *)
  exception_table : data_directory_entry option;  (** Exception table *)
  certificate_table : data_directory_entry option;  (** Certificate table *)
  base_relocation_table : data_directory_entry option;  (** Base relocation table *)
  debug_data : data_directory_entry option;  (** Debug data *)
  architecture_data : data_directory_entry option;  (** Architecture specific data *)
  global_ptr : data_directory_entry option;  (** Global pointer register *)
  tls_table : data_directory_entry option;  (** Thread local storage table *)
  load_config_table : data_directory_entry option;  (** Load configuration table *)
  bound_import_table : data_directory_entry option;  (** Bound import table *)
  import_address_table : data_directory_entry option;  (** Import address table *)
  delay_import_table : data_directory_entry option;  (** Delay import descriptor *)
  com_descriptor : data_directory_entry option;  (** COM+ runtime descriptor *)
  reserved : data_directory_entry option;  (** Reserved *)
}

(** Get a data directory entry by type *)
val get_data_directory_entry : data_directory -> data_directory_type -> data_directory_entry option

(** Check if a data directory entry exists and is non-empty *)
val has_data_directory : data_directory -> data_directory_type -> bool

(** Get the virtual address of a data directory entry *)
val get_data_directory_address : data_directory -> data_directory_type -> u32 option

(** Get the size of a data directory entry *)
val get_data_directory_size : data_directory -> data_directory_type -> u32 option

type optional_header = {
  magic : pe_magic;  (** PE format version *)
  major_linker_version : u8;  (** Major linker version *)
  minor_linker_version : u8;  (** Minor linker version *)
  size_of_code : u32;  (** Total size of code sections *)
  size_of_initialized_data : u32;  (** Total size of initialized data *)
  size_of_uninitialized_data : u32;  (** Total size of uninitialized data *)
  address_of_entry_point : u32;  (** RVA of entry point *)
  base_of_code : u32;  (** RVA of code section base *)
  base_of_data : u32 option;  (** RVA of data section base (PE32 only) *)
  image_base : u64;  (** Preferred load address *)
  section_alignment : u32;  (** Section alignment in memory *)
  file_alignment : u32;  (** Section alignment in file *)
  major_operating_system_version : u16;  (** Major OS version *)
  minor_operating_system_version : u16;  (** Minor OS version *)
  major_image_version : u16;  (** Major image version *)
  minor_image_version : u16;  (** Minor image version *)
  major_subsystem_version : u16;  (** Major subsystem version *)
  minor_subsystem_version : u16;  (** Minor subsystem version *)
  win32_version_value : u32;  (** Win32 version (reserved) *)
  size_of_image : u32;  (** Total image size in memory *)
  size_of_headers : u32;  (** Total header size *)
  checksum : u32;  (** Image checksum *)
  subsystem : u16;  (** Target subsystem *)
  dll_characteristics : u16;  (** DLL characteristics *)
  size_of_stack_reserve : u64;  (** Stack reserve size *)
  size_of_stack_commit : u64;  (** Stack commit size *)
  size_of_heap_reserve : u64;  (** Heap reserve size *)
  size_of_heap_commit : u64;  (** Heap commit size *)
  loader_flags : u32;  (** Loader flags (reserved) *)
  number_of_rva_and_sizes : u32;  (** Number of data directory entries *)
  data_directory : data_directory;  (** Data directory tables *)
}
(** PE optional header structure containing Windows-specific information *)

type section_header = {
  name : string;  (** Section name (up to 8 characters) *)
  virtual_size : u32;  (** Section size in memory *)
  virtual_address : u32;  (** Section RVA when loaded *)
  size_of_raw_data : u32;  (** Section size in file *)
  pointer_to_raw_data : u32;  (** File offset to section data *)
  pointer_to_relocations : u32;  (** File offset to relocations *)
  pointer_to_line_numbers : u32;  (** File offset to line numbers *)
  number_of_relocations : u16;  (** Number of relocation entries *)
  number_of_line_numbers : u16;  (** Number of line number entries *)
  characteristics : section_characteristics list;  (** Section properties *)
}
(** Section header structure (40 bytes) describing individual sections *)

type pe_object = {
  coff_header : coff_header;  (** COFF file header *)
  optional_header : optional_header option;
      (** PE optional header (if present) *)
  section_headers : section_header array;  (** Array of section headers *)
}
(** Complete PE object structure containing all parsed components *)

val is_pe : Buffer.t -> bool
(** [is_pe buffer] returns [true] if the buffer contains a valid PE file. Checks
    for DOS signature "MZ" and PE signature "PE\0\0". *)

val read : Buffer.t -> pe_object
(** [read buffer] parses a PE file from the buffer and returns the complete PE
    object structure with all headers and sections. *)

val sections : pe_object -> section_header array
(** [sections pe_obj] returns the array of section headers from the PE object.
*)

val get_architecture :
  pe_object -> [ `X86 | `X86_64 | `ARM | `ARM64 | `Unknown of int ]
(** [get_architecture pe_obj] returns the target architecture of the PE file. *)

val is_64bit : pe_object -> bool
(** [is_64bit pe_obj] returns [true] if the PE file is 64-bit (PE32+). *)

val is_executable : pe_object -> bool
(** [is_executable pe_obj] returns [true] if the PE file is executable. *)

val entry_point : pe_object -> u64 option
(** [entry_point pe_obj] returns the entry point address if available. *)

val section_characteristics_to_type_string :
  section_characteristics list -> string
(** [section_characteristics_to_type_string characteristics] converts section
    characteristics to a human-readable type string. *)

(** {2 Section Characteristic Utilities} *)

val section_has_characteristic :
  section_header -> section_characteristics -> bool
(** [section_has_characteristic section_header characteristic] returns [true] if
    the section has the specified characteristic flag. *)

val section_is_executable : section_header -> bool
(** [section_is_executable section_header] returns [true] if the section can be
    executed as code (has IMAGE_SCN_MEM_EXECUTE flag). *)

val section_is_writable : section_header -> bool
(** [section_is_writable section_header] returns [true] if the section can be
    written to (has IMAGE_SCN_MEM_WRITE flag). *)

val section_is_readable : section_header -> bool
(** [section_is_readable section_header] returns [true] if the section can be
    read (has IMAGE_SCN_MEM_READ flag). *)

val section_contains_code : section_header -> bool
(** [section_contains_code section_header] returns [true] if the section
    contains executable code (has IMAGE_SCN_CNT_CODE flag). *)

val section_contains_data : section_header -> bool
(** [section_contains_data section_header] returns [true] if the section
    contains initialized or uninitialized data. *)

val section_is_discardable : section_header -> bool
(** [section_is_discardable section_header] returns [true] if the section can be
    discarded as needed (has IMAGE_SCN_MEM_DISCARDABLE flag). *)
