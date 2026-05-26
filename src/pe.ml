open Object_types

(** Windows PE/COFF parser based on
    {:https://docs.microsoft.com/en-us/windows/win32/debug/pe-format}. *)

type machine_type =
  | IMAGE_FILE_MACHINE_I386
  | IMAGE_FILE_MACHINE_AMD64
  | IMAGE_FILE_MACHINE_ARM
  | IMAGE_FILE_MACHINE_ARM64
  | IMAGE_FILE_MACHINE_ARM64EC
  | IMAGE_FILE_MACHINE_ARM64X
  | IMAGE_FILE_MACHINE_IA64
  | IMAGE_FILE_MACHINE_RISCV32
  | IMAGE_FILE_MACHINE_RISCV64
  | IMAGE_FILE_MACHINE_UNKNOWN of u16

type pe_magic = PE32 | PE32PLUS

type section_characteristics =
  | IMAGE_SCN_TYPE_NO_PAD  (** Section should not be padded to next boundary *)
  | IMAGE_SCN_CNT_CODE  (** Section contains executable code *)
  | IMAGE_SCN_CNT_INITIALIZED_DATA  (** Section contains initialised data *)
  | IMAGE_SCN_CNT_UNINITIALIZED_DATA  (** Section contains uninitialised data *)
  | IMAGE_SCN_LNK_INFO  (** Section contains comments or other information *)
  | IMAGE_SCN_LNK_REMOVE  (** Section will not become part of the image *)
  | IMAGE_SCN_LNK_COMDAT  (** Section contains COMDAT data *)
  | IMAGE_SCN_MEM_DISCARDABLE  (** Section can be discarded as needed *)
  | IMAGE_SCN_MEM_NOT_CACHED  (** Section cannot be cached *)
  | IMAGE_SCN_MEM_NOT_PAGED  (** Section is not pageable *)
  | IMAGE_SCN_MEM_SHARED  (** Section can be shared in memory *)
  | IMAGE_SCN_MEM_EXECUTE  (** Section can be executed as code *)
  | IMAGE_SCN_MEM_READ  (** Section can be read *)
  | IMAGE_SCN_MEM_WRITE  (** Section can be written to *)
  | IMAGE_SCN_UNKNOWN of u32  (** Unknown characteristics with raw flags *)

type coff_header = {
  machine : machine_type;
  number_of_sections : u16;
  time_date_stamp : u32;
  pointer_to_symbol_table : u32;
  number_of_symbols : u32;
  size_of_optional_header : u16;
  characteristics : u16;
}

type data_directory_type =
  | IMAGE_DIRECTORY_ENTRY_EXPORT
  | IMAGE_DIRECTORY_ENTRY_IMPORT
  | IMAGE_DIRECTORY_ENTRY_RESOURCE
  | IMAGE_DIRECTORY_ENTRY_EXCEPTION
  | IMAGE_DIRECTORY_ENTRY_SECURITY
  | IMAGE_DIRECTORY_ENTRY_BASERELOC
  | IMAGE_DIRECTORY_ENTRY_DEBUG
  | IMAGE_DIRECTORY_ENTRY_ARCHITECTURE
  | IMAGE_DIRECTORY_ENTRY_GLOBALPTR
  | IMAGE_DIRECTORY_ENTRY_TLS
  | IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
  | IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
  | IMAGE_DIRECTORY_ENTRY_IAT
  | IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
  | IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
  | IMAGE_DIRECTORY_ENTRY_RESERVED

type data_directory_entry = { virtual_address : u32; size : u32 }

type data_directory = {
  export_table : data_directory_entry option;
  import_table : data_directory_entry option;
  resource_table : data_directory_entry option;
  exception_table : data_directory_entry option;
  certificate_table : data_directory_entry option;
  base_relocation_table : data_directory_entry option;
  debug_data : data_directory_entry option;
  architecture_data : data_directory_entry option;
  global_ptr : data_directory_entry option;
  tls_table : data_directory_entry option;
  load_config_table : data_directory_entry option;
  bound_import_table : data_directory_entry option;
  import_address_table : data_directory_entry option;
  delay_import_table : data_directory_entry option;
  com_descriptor : data_directory_entry option;
  reserved : data_directory_entry option;
}

type optional_header = {
  magic : pe_magic;
  major_linker_version : u8;
  minor_linker_version : u8;
  size_of_code : u32;
  size_of_initialized_data : u32;
  size_of_uninitialized_data : u32;
  address_of_entry_point : u32;
  base_of_code : u32;
  base_of_data : u32 option;
  image_base : u64;
  section_alignment : u32;
  file_alignment : u32;
  major_operating_system_version : u16;
  minor_operating_system_version : u16;
  major_image_version : u16;
  minor_image_version : u16;
  major_subsystem_version : u16;
  minor_subsystem_version : u16;
  win32_version_value : u32;
  size_of_image : u32;
  size_of_headers : u32;
  checksum : u32;
  subsystem : u16;
  dll_characteristics : u16;
  size_of_stack_reserve : u64;
  size_of_stack_commit : u64;
  size_of_heap_reserve : u64;
  size_of_heap_commit : u64;
  loader_flags : u32;
  number_of_rva_and_sizes : u32;
  data_directory : data_directory;
}

type section_header = {
  name : string;
  virtual_size : u32;
  virtual_address : u32;
  size_of_raw_data : u32;
  pointer_to_raw_data : u32;
  pointer_to_relocations : u32;
  pointer_to_line_numbers : u32;
  number_of_relocations : u16;
  number_of_line_numbers : u16;
  characteristics : section_characteristics list;
}

let machine_type_of_u16 n =
  match Unsigned.UInt16.to_int n with
  | 0x014c -> IMAGE_FILE_MACHINE_I386
  | 0x8664 -> IMAGE_FILE_MACHINE_AMD64
  | 0x01c0 -> IMAGE_FILE_MACHINE_ARM
  | 0xaa64 -> IMAGE_FILE_MACHINE_ARM64
  | 0xa641 -> IMAGE_FILE_MACHINE_ARM64EC
  | 0xa64e -> IMAGE_FILE_MACHINE_ARM64X
  | 0x0200 -> IMAGE_FILE_MACHINE_IA64
  | 0x5032 -> IMAGE_FILE_MACHINE_RISCV32
  | 0x5064 -> IMAGE_FILE_MACHINE_RISCV64
  | _ -> IMAGE_FILE_MACHINE_UNKNOWN n

let machine_type_to_string = function
  | IMAGE_FILE_MACHINE_I386 -> "i386"
  | IMAGE_FILE_MACHINE_AMD64 -> "amd64"
  | IMAGE_FILE_MACHINE_ARM -> "arm"
  | IMAGE_FILE_MACHINE_ARM64 -> "arm64"
  | IMAGE_FILE_MACHINE_ARM64EC -> "arm64ec"
  | IMAGE_FILE_MACHINE_ARM64X -> "arm64x"
  | IMAGE_FILE_MACHINE_IA64 -> "ia64"
  | IMAGE_FILE_MACHINE_RISCV32 -> "riscv32"
  | IMAGE_FILE_MACHINE_RISCV64 -> "riscv64"
  | IMAGE_FILE_MACHINE_UNKNOWN n ->
      Printf.sprintf "unknown(%d)" (Unsigned.UInt16.to_int n)

let pe_magic_of_u16 = function
  | 0x10b -> PE32
  | 0x20b -> PE32PLUS
  | n -> Buffer.invalid_format (Printf.sprintf "Unknown PE magic: 0x%x" n)

let section_characteristics_flags =
  [
    (0x00000008, IMAGE_SCN_TYPE_NO_PAD);
    (0x00000020, IMAGE_SCN_CNT_CODE);
    (0x00000040, IMAGE_SCN_CNT_INITIALIZED_DATA);
    (0x00000080, IMAGE_SCN_CNT_UNINITIALIZED_DATA);
    (0x00000200, IMAGE_SCN_LNK_INFO);
    (0x00000800, IMAGE_SCN_LNK_REMOVE);
    (0x00001000, IMAGE_SCN_LNK_COMDAT);
    (0x02000000, IMAGE_SCN_MEM_DISCARDABLE);
    (0x04000000, IMAGE_SCN_MEM_NOT_CACHED);
    (0x08000000, IMAGE_SCN_MEM_NOT_PAGED);
    (0x10000000, IMAGE_SCN_MEM_SHARED);
    (0x20000000, IMAGE_SCN_MEM_EXECUTE);
    (0x40000000, IMAGE_SCN_MEM_READ);
    (0x80000000, IMAGE_SCN_MEM_WRITE);
  ]

let section_characteristics_of_u32 flags =
  let flags_int = Unsigned.UInt32.to_int flags in
  let characteristics =
    List.fold_left
      (fun acc (mask, flag) ->
        if flags_int land mask <> 0 then flag :: acc else acc)
      [] section_characteristics_flags
  in
  if characteristics = [] then [ IMAGE_SCN_UNKNOWN flags ] else characteristics

let image_dos_signature = 0x5a4d (* "MZ" *)
let image_nt_signature = 0x00004550 (* "PE\000\000" *)

(* Read the 2-byte DOS signature at the cursor; [true] if it is "MZ". *)
let check_dos_signature cursor =
  Unsigned.UInt16.to_int (Buffer.Read.u16 cursor) = image_dos_signature

(* Read the 4-byte PE signature at the cursor; [true] if it is "PE\0\0". *)
let check_nt_signature cursor =
  Unsigned.UInt32.to_int (Buffer.Read.u32 cursor) = image_nt_signature

(* Truncate [s] at its first NUL byte, as used for fixed-width name fields. *)
let string_until_nul s =
  match String.index_opt s '\000' with Some i -> String.sub s 0 i | None -> s

(* The COFF string table holds names longer than 8 bytes: a 4-byte length
   prefix followed by NUL-terminated strings. We keep the bytes after the
   prefix, so a reference into the table (which counts the prefix) resolves at
   [offset - 4]. *)
type string_table = string

let string_table_get (tbl : string_table) offset =
  let i = offset - 4 in
  if i < 0 || i >= String.length tbl then ""
  else
    let stop =
      match String.index_from_opt tbl i '\000' with
      | Some j -> j
      | None -> String.length tbl
    in
    String.sub tbl i (stop - i)

(* A section name of the form "/N" refers to byte offset N in the string table;
   anything else is the literal 8-byte name. *)
let resolve_section_name string_table raw =
  if String.length raw >= 2 && raw.[0] = '/' then
    match string_table with
    | Some tbl -> (
        match int_of_string_opt (String.sub raw 1 (String.length raw - 1)) with
        | Some n -> string_table_get tbl n
        | None -> raw)
    | None -> raw
  else raw

let is_pe buffer =
  try
    let cursor = Buffer.cursor buffer in
    Buffer.ensure cursor 2 "PE detection: insufficient data for DOS signature";
    if not (check_dos_signature cursor) then false
    else (
      Buffer.ensure cursor 58 "PE detection: insufficient data for DOS header";
      Buffer.seek cursor 60;
      let pe_header_offset = Buffer.Read.u32 cursor in
      let pe_offset = Unsigned.UInt32.to_int pe_header_offset in
      Buffer.ensure cursor (pe_offset + 4)
        "PE detection: insufficient data for PE signature";
      Buffer.seek cursor pe_offset;
      check_nt_signature cursor)
  with Buffer.Invalid_format _ -> false

let find_pe_header_offset buffer =
  let cursor = Buffer.cursor buffer in
  Buffer.ensure cursor 2 "DOS signature check";
  if not (check_dos_signature cursor) then
    Buffer.invalid_format "Not a DOS/PE file: missing DOS signature";
  Buffer.seek cursor 60;
  let pe_header_offset = Buffer.Read.u32 cursor in
  Unsigned.UInt32.to_int pe_header_offset

(* A bare COFF object has no DOS/PE header; it begins with a COFF header whose
   first field is a recognised machine type. *)
let is_coff buffer =
  try
    let cursor = Buffer.cursor buffer in
    Buffer.ensure cursor 2 "COFF machine type";
    match machine_type_of_u16 (Buffer.Read.u16 cursor) with
    | IMAGE_FILE_MACHINE_UNKNOWN _ -> false
    | _ -> true
  with Buffer.Invalid_format _ -> false

let read_coff_header cursor =
  let open Buffer.Read in
  Buffer.ensure cursor 20 "COFF header";
  let machine = machine_type_of_u16 (u16 cursor) in
  let number_of_sections = u16 cursor in
  let time_date_stamp = u32 cursor in
  let pointer_to_symbol_table = u32 cursor in
  let number_of_symbols = u32 cursor in
  let size_of_optional_header = u16 cursor in
  let characteristics = u16 cursor in
  {
    machine;
    number_of_sections;
    time_date_stamp;
    pointer_to_symbol_table;
    number_of_symbols;
    size_of_optional_header;
    characteristics;
  }

let read_data_directory_entry cursor =
  let open Buffer.Read in
  let virtual_address = u32 cursor in
  let size = u32 cursor in
  if Unsigned.UInt32.(to_int virtual_address = 0 && to_int size = 0) then None
  else Some { virtual_address; size }

let read_data_directory cursor num_entries =
  let count = min (Unsigned.UInt32.to_int num_entries) 16 in
  Buffer.ensure cursor (count * 8) "Optional header data directory";
  let entries = Array.make 16 None in
  for i = 0 to count - 1 do
    entries.(i) <- read_data_directory_entry cursor
  done;
  {
    export_table = entries.(0);
    import_table = entries.(1);
    resource_table = entries.(2);
    exception_table = entries.(3);
    certificate_table = entries.(4);
    base_relocation_table = entries.(5);
    debug_data = entries.(6);
    architecture_data = entries.(7);
    global_ptr = entries.(8);
    tls_table = entries.(9);
    load_config_table = entries.(10);
    bound_import_table = entries.(11);
    import_address_table = entries.(12);
    delay_import_table = entries.(13);
    com_descriptor = entries.(14);
    reserved = entries.(15);
  }

let get_data_directory_entry data_directory = function
  | IMAGE_DIRECTORY_ENTRY_EXPORT -> data_directory.export_table
  | IMAGE_DIRECTORY_ENTRY_IMPORT -> data_directory.import_table
  | IMAGE_DIRECTORY_ENTRY_RESOURCE -> data_directory.resource_table
  | IMAGE_DIRECTORY_ENTRY_EXCEPTION -> data_directory.exception_table
  | IMAGE_DIRECTORY_ENTRY_SECURITY -> data_directory.certificate_table
  | IMAGE_DIRECTORY_ENTRY_BASERELOC -> data_directory.base_relocation_table
  | IMAGE_DIRECTORY_ENTRY_DEBUG -> data_directory.debug_data
  | IMAGE_DIRECTORY_ENTRY_ARCHITECTURE -> data_directory.architecture_data
  | IMAGE_DIRECTORY_ENTRY_GLOBALPTR -> data_directory.global_ptr
  | IMAGE_DIRECTORY_ENTRY_TLS -> data_directory.tls_table
  | IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG -> data_directory.load_config_table
  | IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT -> data_directory.bound_import_table
  | IMAGE_DIRECTORY_ENTRY_IAT -> data_directory.import_address_table
  | IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT -> data_directory.delay_import_table
  | IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR -> data_directory.com_descriptor
  | IMAGE_DIRECTORY_ENTRY_RESERVED -> data_directory.reserved

let has_data_directory data_directory dir_type =
  match get_data_directory_entry data_directory dir_type with
  | Some entry ->
      Unsigned.UInt32.(
        to_int entry.virtual_address <> 0 || to_int entry.size <> 0)
  | None -> false

let get_data_directory_address data_directory dir_type =
  match get_data_directory_entry data_directory dir_type with
  | Some entry -> Some entry.virtual_address
  | None -> None

let get_data_directory_size data_directory dir_type =
  match get_data_directory_entry data_directory dir_type with
  | Some entry -> Some entry.size
  | None -> None

(* Read a 32-bit field and widen it to [u64], for fields that are 32-bit in
   PE32 but 64-bit in PE32+. *)
let read_u32_as_u64 cursor = u32_to_u64 (Buffer.Read.u32 cursor)

let read_optional_header cursor optional_header_size =
  let open Buffer.Read in
  if Unsigned.UInt16.to_int optional_header_size < 24 then
    Buffer.invalid_format "Optional header too small";

  Buffer.ensure cursor 24 "Optional header standard fields";
  let magic = pe_magic_of_u16 (Unsigned.UInt16.to_int (u16 cursor)) in
  let major_linker_version = u8 cursor in
  let minor_linker_version = u8 cursor in
  let size_of_code = u32 cursor in
  let size_of_initialized_data = u32 cursor in
  let size_of_uninitialized_data = u32 cursor in
  let address_of_entry_point = u32 cursor in
  let base_of_code = u32 cursor in

  let base_of_data, image_base =
    match magic with
    | PE32 ->
        Buffer.ensure cursor 8 "PE32 additional fields";
        let base_of_data = Some (u32 cursor) in
        let image_base = read_u32_as_u64 cursor in
        (base_of_data, image_base)
    | PE32PLUS ->
        Buffer.ensure cursor 8 "PE32+ image base";
        let image_base = u64 cursor in
        (None, image_base)
  in

  Buffer.ensure cursor 68 "Optional header Windows fields";
  let section_alignment = u32 cursor in
  let file_alignment = u32 cursor in
  let major_operating_system_version = u16 cursor in
  let minor_operating_system_version = u16 cursor in
  let major_image_version = u16 cursor in
  let minor_image_version = u16 cursor in
  let major_subsystem_version = u16 cursor in
  let minor_subsystem_version = u16 cursor in
  let win32_version_value = u32 cursor in
  let size_of_image = u32 cursor in
  let size_of_headers = u32 cursor in
  let checksum = u32 cursor in
  let subsystem = u16 cursor in
  let dll_characteristics = u16 cursor in

  let ( size_of_stack_reserve,
        size_of_stack_commit,
        size_of_heap_reserve,
        size_of_heap_commit ) =
    match magic with
    | PE32 ->
        Buffer.ensure cursor 16 "PE32 size fields";
        let stack_reserve = read_u32_as_u64 cursor in
        let stack_commit = read_u32_as_u64 cursor in
        let heap_reserve = read_u32_as_u64 cursor in
        let heap_commit = read_u32_as_u64 cursor in
        (stack_reserve, stack_commit, heap_reserve, heap_commit)
    | PE32PLUS ->
        Buffer.ensure cursor 32 "PE32+ size fields";
        let stack_reserve = u64 cursor in
        let stack_commit = u64 cursor in
        let heap_reserve = u64 cursor in
        let heap_commit = u64 cursor in
        (stack_reserve, stack_commit, heap_reserve, heap_commit)
  in

  Buffer.ensure cursor 8 "Optional header final fields";
  let loader_flags = u32 cursor in
  let number_of_rva_and_sizes = u32 cursor in

  (* Read data directory entries *)
  let data_directory = read_data_directory cursor number_of_rva_and_sizes in

  {
    magic;
    major_linker_version;
    minor_linker_version;
    size_of_code;
    size_of_initialized_data;
    size_of_uninitialized_data;
    address_of_entry_point;
    base_of_code;
    base_of_data;
    image_base;
    section_alignment;
    file_alignment;
    major_operating_system_version;
    minor_operating_system_version;
    major_image_version;
    minor_image_version;
    major_subsystem_version;
    minor_subsystem_version;
    win32_version_value;
    size_of_image;
    size_of_headers;
    checksum;
    subsystem;
    dll_characteristics;
    size_of_stack_reserve;
    size_of_stack_commit;
    size_of_heap_reserve;
    size_of_heap_commit;
    loader_flags;
    number_of_rva_and_sizes;
    data_directory;
  }

let read_section_header ?string_table cursor =
  let open Buffer.Read in
  Buffer.ensure cursor 40 "Section header";
  let raw_name = string_until_nul (fixed_string cursor 8) in
  let name = resolve_section_name string_table raw_name in
  let virtual_size = u32 cursor in
  let virtual_address = u32 cursor in
  let size_of_raw_data = u32 cursor in
  let pointer_to_raw_data = u32 cursor in
  let pointer_to_relocations = u32 cursor in
  let pointer_to_line_numbers = u32 cursor in
  let number_of_relocations = u16 cursor in
  let number_of_line_numbers = u16 cursor in
  let characteristics_raw = u32 cursor in
  let characteristics = section_characteristics_of_u32 characteristics_raw in
  {
    name;
    virtual_size;
    virtual_address;
    size_of_raw_data;
    pointer_to_raw_data;
    pointer_to_relocations;
    pointer_to_line_numbers;
    number_of_relocations;
    number_of_line_numbers;
    characteristics;
  }

let read_section_headers ?string_table cursor number_of_sections =
  Array.init (Unsigned.UInt16.to_int number_of_sections) (fun _ ->
      read_section_header ?string_table cursor)

let machine_to_arch = function
  | IMAGE_FILE_MACHINE_I386 -> `X86
  | IMAGE_FILE_MACHINE_AMD64 -> `X86_64
  | IMAGE_FILE_MACHINE_ARM -> `ARM
  | IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARM64EC
  | IMAGE_FILE_MACHINE_ARM64X ->
      `ARM64
  | IMAGE_FILE_MACHINE_IA64 -> `Unknown 0x0200
  | IMAGE_FILE_MACHINE_RISCV32 -> `Unknown 0x5032
  | IMAGE_FILE_MACHINE_RISCV64 -> `Unknown 0x5064
  | IMAGE_FILE_MACHINE_UNKNOWN n -> `Unknown (Unsigned.UInt16.to_int n)

let section_characteristics_to_type_string characteristics =
  let has_char char = List.mem char characteristics in
  if has_char IMAGE_SCN_CNT_CODE then "CODE"
  else if has_char IMAGE_SCN_CNT_INITIALIZED_DATA then "DATA"
  else if has_char IMAGE_SCN_CNT_UNINITIALIZED_DATA then "BSS"
  else if has_char IMAGE_SCN_LNK_INFO then "INFO"
  else if has_char IMAGE_SCN_LNK_REMOVE then "REMOVE"
  else if has_char IMAGE_SCN_LNK_COMDAT then "COMDAT"
  else "UNKNOWN"

(* The string table immediately follows the symbol table, at
   [pointer_to_symbol_table + number_of_symbols * 18]. Its first 4 bytes are the
   total table size (counting those 4 bytes). *)
let read_string_table buf (coff : coff_header) : string_table option =
  let symtab = Unsigned.UInt32.to_int coff.pointer_to_symbol_table in
  if symtab = 0 then None
  else
    let nsyms = Unsigned.UInt32.to_int coff.number_of_symbols in
    let cursor = Buffer.cursor ~at:(symtab + (nsyms * 18)) buf in
    Buffer.ensure cursor 4 "COFF string table size";
    let size = Unsigned.UInt32.to_int (Buffer.Read.u32 cursor) in
    if size <= 4 then Some ""
    else begin
      Buffer.ensure cursor (size - 4) "COFF string table";
      Some (Buffer.Read.fixed_string cursor (size - 4))
    end

type pe_object = {
  coff_header : coff_header;
  optional_header : optional_header option;
  string_table : string_table option;
  section_headers : section_header array;
}

let read buffer =
  let cursor =
    if is_pe buffer then begin
      let cursor = Buffer.cursor ~at:(find_pe_header_offset buffer) buffer in
      Buffer.ensure cursor 4 "PE signature";
      if not (check_nt_signature cursor) then
        Buffer.invalid_format "Not a PE file: missing PE signature";
      cursor
    end
    else if is_coff buffer then Buffer.cursor buffer
    else Buffer.invalid_format "Not a PE or COFF file"
  in
  let coff_header = read_coff_header cursor in
  let optional_header =
    if Unsigned.UInt16.to_int coff_header.size_of_optional_header > 0 then
      Some (read_optional_header cursor coff_header.size_of_optional_header)
    else None
  in
  let string_table = read_string_table buffer coff_header in
  let section_headers =
    read_section_headers ?string_table cursor coff_header.number_of_sections
  in
  { coff_header; optional_header; string_table; section_headers }

(** {2 Symbol Table}

    The COFF symbol table is an array of 18-byte records at
    [pointer_to_symbol_table]. A primary record may be followed by auxiliary
    records (all counted by [number_of_symbols]); we return the primary records
    with their auxiliary records decoded. *)

type storage_class =
  | IMAGE_SYM_CLASS_NULL
  | IMAGE_SYM_CLASS_AUTOMATIC
  | IMAGE_SYM_CLASS_EXTERNAL
  | IMAGE_SYM_CLASS_STATIC
  | IMAGE_SYM_CLASS_REGISTER
  | IMAGE_SYM_CLASS_EXTERNAL_DEF
  | IMAGE_SYM_CLASS_LABEL
  | IMAGE_SYM_CLASS_UNDEFINED_LABEL
  | IMAGE_SYM_CLASS_MEMBER_OF_STRUCT
  | IMAGE_SYM_CLASS_ARGUMENT
  | IMAGE_SYM_CLASS_STRUCT_TAG
  | IMAGE_SYM_CLASS_MEMBER_OF_UNION
  | IMAGE_SYM_CLASS_UNION_TAG
  | IMAGE_SYM_CLASS_TYPE_DEFINITION
  | IMAGE_SYM_CLASS_UNDEFINED_STATIC
  | IMAGE_SYM_CLASS_ENUM_TAG
  | IMAGE_SYM_CLASS_MEMBER_OF_ENUM
  | IMAGE_SYM_CLASS_REGISTER_PARAM
  | IMAGE_SYM_CLASS_BIT_FIELD
  | IMAGE_SYM_CLASS_BLOCK
  | IMAGE_SYM_CLASS_FUNCTION
  | IMAGE_SYM_CLASS_END_OF_STRUCT
  | IMAGE_SYM_CLASS_FILE
  | IMAGE_SYM_CLASS_SECTION
  | IMAGE_SYM_CLASS_WEAK_EXTERNAL
  | IMAGE_SYM_CLASS_CLR_TOKEN
  | IMAGE_SYM_CLASS_END_OF_FUNCTION
  | IMAGE_SYM_CLASS_UNKNOWN of u8

let storage_class_of_u8 b =
  match Unsigned.UInt8.to_int b with
  | 0xff -> IMAGE_SYM_CLASS_END_OF_FUNCTION
  | 0 -> IMAGE_SYM_CLASS_NULL
  | 1 -> IMAGE_SYM_CLASS_AUTOMATIC
  | 2 -> IMAGE_SYM_CLASS_EXTERNAL
  | 3 -> IMAGE_SYM_CLASS_STATIC
  | 4 -> IMAGE_SYM_CLASS_REGISTER
  | 5 -> IMAGE_SYM_CLASS_EXTERNAL_DEF
  | 6 -> IMAGE_SYM_CLASS_LABEL
  | 7 -> IMAGE_SYM_CLASS_UNDEFINED_LABEL
  | 8 -> IMAGE_SYM_CLASS_MEMBER_OF_STRUCT
  | 9 -> IMAGE_SYM_CLASS_ARGUMENT
  | 10 -> IMAGE_SYM_CLASS_STRUCT_TAG
  | 11 -> IMAGE_SYM_CLASS_MEMBER_OF_UNION
  | 12 -> IMAGE_SYM_CLASS_UNION_TAG
  | 13 -> IMAGE_SYM_CLASS_TYPE_DEFINITION
  | 14 -> IMAGE_SYM_CLASS_UNDEFINED_STATIC
  | 15 -> IMAGE_SYM_CLASS_ENUM_TAG
  | 16 -> IMAGE_SYM_CLASS_MEMBER_OF_ENUM
  | 17 -> IMAGE_SYM_CLASS_REGISTER_PARAM
  | 18 -> IMAGE_SYM_CLASS_BIT_FIELD
  | 100 -> IMAGE_SYM_CLASS_BLOCK
  | 101 -> IMAGE_SYM_CLASS_FUNCTION
  | 102 -> IMAGE_SYM_CLASS_END_OF_STRUCT
  | 103 -> IMAGE_SYM_CLASS_FILE
  | 104 -> IMAGE_SYM_CLASS_SECTION
  | 105 -> IMAGE_SYM_CLASS_WEAK_EXTERNAL
  | 107 -> IMAGE_SYM_CLASS_CLR_TOKEN
  | _ -> IMAGE_SYM_CLASS_UNKNOWN b

(* The symbol Type field splits into a base type (low nibble) and a derived,
   "complex" type (next nibble); a function has complex type FUNCTION. *)
type symbol_base_type =
  | IMAGE_SYM_TYPE_NULL
  | IMAGE_SYM_TYPE_VOID
  | IMAGE_SYM_TYPE_CHAR
  | IMAGE_SYM_TYPE_SHORT
  | IMAGE_SYM_TYPE_INT
  | IMAGE_SYM_TYPE_LONG
  | IMAGE_SYM_TYPE_FLOAT
  | IMAGE_SYM_TYPE_DOUBLE
  | IMAGE_SYM_TYPE_STRUCT
  | IMAGE_SYM_TYPE_UNION
  | IMAGE_SYM_TYPE_ENUM
  | IMAGE_SYM_TYPE_MOE
  | IMAGE_SYM_TYPE_BYTE
  | IMAGE_SYM_TYPE_WORD
  | IMAGE_SYM_TYPE_UINT
  | IMAGE_SYM_TYPE_DWORD
  | IMAGE_SYM_TYPE_UNKNOWN of int

type symbol_complex_type =
  | IMAGE_SYM_DTYPE_NULL
  | IMAGE_SYM_DTYPE_POINTER
  | IMAGE_SYM_DTYPE_FUNCTION
  | IMAGE_SYM_DTYPE_ARRAY
  | IMAGE_SYM_DTYPE_UNKNOWN of int

type symbol_type = {
  base_type : symbol_base_type;
  complex_type : symbol_complex_type;
}

let symbol_base_type_of_int = function
  | 0 -> IMAGE_SYM_TYPE_NULL
  | 1 -> IMAGE_SYM_TYPE_VOID
  | 2 -> IMAGE_SYM_TYPE_CHAR
  | 3 -> IMAGE_SYM_TYPE_SHORT
  | 4 -> IMAGE_SYM_TYPE_INT
  | 5 -> IMAGE_SYM_TYPE_LONG
  | 6 -> IMAGE_SYM_TYPE_FLOAT
  | 7 -> IMAGE_SYM_TYPE_DOUBLE
  | 8 -> IMAGE_SYM_TYPE_STRUCT
  | 9 -> IMAGE_SYM_TYPE_UNION
  | 10 -> IMAGE_SYM_TYPE_ENUM
  | 11 -> IMAGE_SYM_TYPE_MOE
  | 12 -> IMAGE_SYM_TYPE_BYTE
  | 13 -> IMAGE_SYM_TYPE_WORD
  | 14 -> IMAGE_SYM_TYPE_UINT
  | 15 -> IMAGE_SYM_TYPE_DWORD
  | n -> IMAGE_SYM_TYPE_UNKNOWN n

let symbol_complex_type_of_int = function
  | 0 -> IMAGE_SYM_DTYPE_NULL
  | 1 -> IMAGE_SYM_DTYPE_POINTER
  | 2 -> IMAGE_SYM_DTYPE_FUNCTION
  | 3 -> IMAGE_SYM_DTYPE_ARRAY
  | n -> IMAGE_SYM_DTYPE_UNKNOWN n

let symbol_type_of_u16 t =
  let t = Unsigned.UInt16.to_int t in
  {
    base_type = symbol_base_type_of_int (t land 0xf);
    complex_type = symbol_complex_type_of_int ((t lsr 4) land 0xf);
  }

(** An auxiliary symbol record, decoded according to the storage class of the
    primary symbol it follows. *)
type aux =
  | Aux_file of string  (** [.file] symbol: the source file name *)
  | Aux_function_definition of {
      tag_index : u32;
      total_size : u32;
      pointer_to_line_number : u32;
      pointer_to_next_function : u32;
    }
  | Aux_function_boundary of {
      line_number : int;
      pointer_to_next_function : u32;
    }  (** [.bf]/[.ef] line-number records *)
  | Aux_weak_external of { tag_index : u32; characteristics : u32 }
  | Aux_section_definition of {
      length : u32;
      number_of_relocations : int;
      number_of_line_numbers : int;
      checksum : u32;
      number : int;
      selection : int;
    }
  | Aux_unknown of string  (** Raw 18 bytes for an undecoded record *)

type symbol = {
  sym_name : string;
  sym_value : u32;
  sym_section_number : int;
  sym_type : symbol_type;
  sym_storage_class : storage_class;
  sym_number_of_aux_symbols : u8;
  sym_aux : aux list;
}

(* The 8-byte name field is either an inline NUL-padded name, or, when its first
   four bytes are zero, a u32 offset into the string table. *)
let symbol_name string_table name_field =
  if
    String.length name_field >= 8
    && name_field.[0] = '\000'
    && name_field.[1] = '\000'
    && name_field.[2] = '\000'
    && name_field.[3] = '\000'
  then
    let off =
      Char.code name_field.[4]
      lor (Char.code name_field.[5] lsl 8)
      lor (Char.code name_field.[6] lsl 16)
      lor (Char.code name_field.[7] lsl 24)
    in
    match string_table with Some tbl -> string_table_get tbl off | None -> ""
  else string_until_nul name_field

(* Little-endian field readers over a raw auxiliary record. *)
let u32_at s off =
  Unsigned.UInt32.of_int
    (Char.code s.[off]
    lor (Char.code s.[off + 1] lsl 8)
    lor (Char.code s.[off + 2] lsl 16)
    lor (Char.code s.[off + 3] lsl 24))

let u16_at s off = Char.code s.[off] lor (Char.code s.[off + 1] lsl 8)

(* A [.file] name is the concatenation of its aux records, or a string-table
   reference when the first four bytes are zero. *)
let aux_file_name string_table raws =
  match raws with
  | first :: _
    when String.length first >= 8
         && first.[0] = '\000'
         && first.[1] = '\000'
         && first.[2] = '\000'
         && first.[3] = '\000' -> (
      let off = Unsigned.UInt32.to_int (u32_at first 4) in
      match string_table with Some t -> string_table_get t off | None -> "")
  | _ -> string_until_nul (String.concat "" raws)

let decode_struct_aux sym raw =
  match sym.sym_storage_class with
  | IMAGE_SYM_CLASS_EXTERNAL
    when sym.sym_type.complex_type = IMAGE_SYM_DTYPE_FUNCTION
         && sym.sym_section_number > 0 ->
      Aux_function_definition
        {
          tag_index = u32_at raw 0;
          total_size = u32_at raw 4;
          pointer_to_line_number = u32_at raw 8;
          pointer_to_next_function = u32_at raw 12;
        }
  | IMAGE_SYM_CLASS_FUNCTION ->
      Aux_function_boundary
        { line_number = u16_at raw 4; pointer_to_next_function = u32_at raw 12 }
  | IMAGE_SYM_CLASS_WEAK_EXTERNAL ->
      Aux_weak_external
        { tag_index = u32_at raw 0; characteristics = u32_at raw 4 }
  | IMAGE_SYM_CLASS_STATIC ->
      Aux_section_definition
        {
          length = u32_at raw 0;
          number_of_relocations = u16_at raw 4;
          number_of_line_numbers = u16_at raw 6;
          checksum = u32_at raw 8;
          number = u16_at raw 12;
          selection = Char.code raw.[14];
        }
  | _ -> Aux_unknown raw

let decode_aux string_table sym raws =
  match sym.sym_storage_class with
  | IMAGE_SYM_CLASS_FILE -> [ Aux_file (aux_file_name string_table raws) ]
  | _ -> List.map (decode_struct_aux sym) raws

let read_symbol_record ?string_table cursor =
  let open Buffer.Read in
  Buffer.ensure cursor 18 "COFF symbol record";
  let name_field = fixed_string cursor 8 in
  let sym_value = u32 cursor in
  let section_raw = Unsigned.UInt16.to_int (u16 cursor) in
  let sym_type = symbol_type_of_u16 (u16 cursor) in
  let sym_storage_class = storage_class_of_u8 (u8 cursor) in
  let sym_number_of_aux_symbols = u8 cursor in
  let sym_section_number =
    if section_raw >= 0x8000 then section_raw - 0x10000 else section_raw
  in
  {
    sym_name = symbol_name string_table name_field;
    sym_value;
    sym_section_number;
    sym_type;
    sym_storage_class;
    sym_number_of_aux_symbols;
    sym_aux = [];
  }

let read_symbols buf pe_obj =
  let coff = pe_obj.coff_header in
  let string_table = pe_obj.string_table in
  let symtab = Unsigned.UInt32.to_int coff.pointer_to_symbol_table in
  if symtab = 0 then [||]
  else begin
    let total = Unsigned.UInt32.to_int coff.number_of_symbols in
    let cursor = Buffer.cursor ~at:symtab buf in
    let acc = ref [] in
    let i = ref 0 in
    while !i < total do
      let sym = read_symbol_record ?string_table cursor in
      let aux_count = Unsigned.UInt8.to_int sym.sym_number_of_aux_symbols in
      let raws = ref [] in
      for _ = 1 to aux_count do
        Buffer.ensure cursor 18 "COFF auxiliary symbol record";
        raws := Buffer.Read.fixed_string cursor 18 :: !raws
      done;
      let sym_aux = decode_aux string_table sym (List.rev !raws) in
      acc := { sym with sym_aux } :: !acc;
      i := !i + 1 + aux_count
    done;
    Array.of_list (List.rev !acc)
  end

(** {2 Relocations}

    Each section may carry an array of 10-byte relocation records at
    [pointer_to_relocations]. The relocation type is machine-dependent. *)

type amd64_relocation =
  | IMAGE_REL_AMD64_ABSOLUTE
  | IMAGE_REL_AMD64_ADDR64
  | IMAGE_REL_AMD64_ADDR32
  | IMAGE_REL_AMD64_ADDR32NB
  | IMAGE_REL_AMD64_REL32
  | IMAGE_REL_AMD64_REL32_1
  | IMAGE_REL_AMD64_REL32_2
  | IMAGE_REL_AMD64_REL32_3
  | IMAGE_REL_AMD64_REL32_4
  | IMAGE_REL_AMD64_REL32_5
  | IMAGE_REL_AMD64_SECTION
  | IMAGE_REL_AMD64_SECREL
  | IMAGE_REL_AMD64_SECREL7
  | IMAGE_REL_AMD64_TOKEN
  | IMAGE_REL_AMD64_SREL32
  | IMAGE_REL_AMD64_PAIR
  | IMAGE_REL_AMD64_SSPAN32
  | IMAGE_REL_AMD64_UNKNOWN of u16

type i386_relocation =
  | IMAGE_REL_I386_ABSOLUTE
  | IMAGE_REL_I386_DIR16
  | IMAGE_REL_I386_REL16
  | IMAGE_REL_I386_DIR32
  | IMAGE_REL_I386_DIR32NB
  | IMAGE_REL_I386_SEG12
  | IMAGE_REL_I386_SECTION
  | IMAGE_REL_I386_SECREL
  | IMAGE_REL_I386_TOKEN
  | IMAGE_REL_I386_SECREL7
  | IMAGE_REL_I386_REL32
  | IMAGE_REL_I386_UNKNOWN of u16

type arm64_relocation =
  | IMAGE_REL_ARM64_ABSOLUTE
  | IMAGE_REL_ARM64_ADDR32
  | IMAGE_REL_ARM64_ADDR32NB
  | IMAGE_REL_ARM64_BRANCH26
  | IMAGE_REL_ARM64_PAGEBASE_REL21
  | IMAGE_REL_ARM64_REL21
  | IMAGE_REL_ARM64_PAGEOFFSET_12A
  | IMAGE_REL_ARM64_PAGEOFFSET_12L
  | IMAGE_REL_ARM64_SECREL
  | IMAGE_REL_ARM64_SECREL_LOW12A
  | IMAGE_REL_ARM64_SECREL_HIGH12A
  | IMAGE_REL_ARM64_SECREL_LOW12L
  | IMAGE_REL_ARM64_TOKEN
  | IMAGE_REL_ARM64_SECTION
  | IMAGE_REL_ARM64_ADDR64
  | IMAGE_REL_ARM64_BRANCH19
  | IMAGE_REL_ARM64_BRANCH14
  | IMAGE_REL_ARM64_REL32
  | IMAGE_REL_ARM64_UNKNOWN of u16

type relocation_type =
  | Reloc_amd64 of amd64_relocation
  | Reloc_i386 of i386_relocation
  | Reloc_arm64 of arm64_relocation
  | Reloc_other of u16  (** A machine without a decoder for its relocations *)

type relocation = {
  reloc_virtual_address : u32;
  reloc_symbol_table_index : u32;
  reloc_type : relocation_type;
}

let amd64_relocation_of_u16 t =
  match Unsigned.UInt16.to_int t with
  | 0x0 -> IMAGE_REL_AMD64_ABSOLUTE
  | 0x1 -> IMAGE_REL_AMD64_ADDR64
  | 0x2 -> IMAGE_REL_AMD64_ADDR32
  | 0x3 -> IMAGE_REL_AMD64_ADDR32NB
  | 0x4 -> IMAGE_REL_AMD64_REL32
  | 0x5 -> IMAGE_REL_AMD64_REL32_1
  | 0x6 -> IMAGE_REL_AMD64_REL32_2
  | 0x7 -> IMAGE_REL_AMD64_REL32_3
  | 0x8 -> IMAGE_REL_AMD64_REL32_4
  | 0x9 -> IMAGE_REL_AMD64_REL32_5
  | 0xa -> IMAGE_REL_AMD64_SECTION
  | 0xb -> IMAGE_REL_AMD64_SECREL
  | 0xc -> IMAGE_REL_AMD64_SECREL7
  | 0xd -> IMAGE_REL_AMD64_TOKEN
  | 0xe -> IMAGE_REL_AMD64_SREL32
  | 0xf -> IMAGE_REL_AMD64_PAIR
  | 0x10 -> IMAGE_REL_AMD64_SSPAN32
  | _ -> IMAGE_REL_AMD64_UNKNOWN t

let i386_relocation_of_u16 t =
  match Unsigned.UInt16.to_int t with
  | 0x0 -> IMAGE_REL_I386_ABSOLUTE
  | 0x1 -> IMAGE_REL_I386_DIR16
  | 0x2 -> IMAGE_REL_I386_REL16
  | 0x6 -> IMAGE_REL_I386_DIR32
  | 0x7 -> IMAGE_REL_I386_DIR32NB
  | 0x9 -> IMAGE_REL_I386_SEG12
  | 0xa -> IMAGE_REL_I386_SECTION
  | 0xb -> IMAGE_REL_I386_SECREL
  | 0xc -> IMAGE_REL_I386_TOKEN
  | 0xd -> IMAGE_REL_I386_SECREL7
  | 0x14 -> IMAGE_REL_I386_REL32
  | _ -> IMAGE_REL_I386_UNKNOWN t

let arm64_relocation_of_u16 t =
  match Unsigned.UInt16.to_int t with
  | 0x0 -> IMAGE_REL_ARM64_ABSOLUTE
  | 0x1 -> IMAGE_REL_ARM64_ADDR32
  | 0x2 -> IMAGE_REL_ARM64_ADDR32NB
  | 0x3 -> IMAGE_REL_ARM64_BRANCH26
  | 0x4 -> IMAGE_REL_ARM64_PAGEBASE_REL21
  | 0x5 -> IMAGE_REL_ARM64_REL21
  | 0x6 -> IMAGE_REL_ARM64_PAGEOFFSET_12A
  | 0x7 -> IMAGE_REL_ARM64_PAGEOFFSET_12L
  | 0x8 -> IMAGE_REL_ARM64_SECREL
  | 0x9 -> IMAGE_REL_ARM64_SECREL_LOW12A
  | 0xa -> IMAGE_REL_ARM64_SECREL_HIGH12A
  | 0xb -> IMAGE_REL_ARM64_SECREL_LOW12L
  | 0xc -> IMAGE_REL_ARM64_TOKEN
  | 0xd -> IMAGE_REL_ARM64_SECTION
  | 0xe -> IMAGE_REL_ARM64_ADDR64
  | 0xf -> IMAGE_REL_ARM64_BRANCH19
  | 0x10 -> IMAGE_REL_ARM64_BRANCH14
  | 0x11 -> IMAGE_REL_ARM64_REL32
  | _ -> IMAGE_REL_ARM64_UNKNOWN t

let relocation_type_of_u16 machine t =
  match machine with
  | IMAGE_FILE_MACHINE_AMD64 -> Reloc_amd64 (amd64_relocation_of_u16 t)
  | IMAGE_FILE_MACHINE_I386 -> Reloc_i386 (i386_relocation_of_u16 t)
  | IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARM64EC
  | IMAGE_FILE_MACHINE_ARM64X ->
      Reloc_arm64 (arm64_relocation_of_u16 t)
  | _ -> Reloc_other t

let read_relocation machine cursor =
  let open Buffer.Read in
  Buffer.ensure cursor 10 "COFF relocation record";
  let reloc_virtual_address = u32 cursor in
  let reloc_symbol_table_index = u32 cursor in
  let reloc_type = relocation_type_of_u16 machine (u16 cursor) in
  { reloc_virtual_address; reloc_symbol_table_index; reloc_type }

let read_relocations buf pe_obj (sh : section_header) =
  let offset = Unsigned.UInt32.to_int sh.pointer_to_relocations in
  let count = Unsigned.UInt16.to_int sh.number_of_relocations in
  if offset = 0 || count = 0 then [||]
  else
    let machine = pe_obj.coff_header.machine in
    let cursor = Buffer.cursor ~at:offset buf in
    Array.init count (fun _ -> read_relocation machine cursor)

let is_64bit pe_obj =
  match pe_obj.optional_header with
  | Some opt -> opt.magic = PE32PLUS
  | None -> false

let is_executable pe_obj =
  Unsigned.UInt16.to_int pe_obj.coff_header.characteristics land 0x2 <> 0

let entry_point pe_obj =
  match pe_obj.optional_header with
  | Some opt when u32_to_int opt.address_of_entry_point <> 0 ->
      Some
        (Unsigned.UInt64.add opt.image_base
           (u32_to_u64 opt.address_of_entry_point))
  | _ -> None

let section_has_characteristic section_header characteristic =
  List.mem characteristic section_header.characteristics

let section_is_executable section_header =
  section_has_characteristic section_header IMAGE_SCN_MEM_EXECUTE

let section_is_writable section_header =
  section_has_characteristic section_header IMAGE_SCN_MEM_WRITE

let section_is_readable section_header =
  section_has_characteristic section_header IMAGE_SCN_MEM_READ

let section_contains_code section_header =
  section_has_characteristic section_header IMAGE_SCN_CNT_CODE

let section_contains_data section_header =
  section_has_characteristic section_header IMAGE_SCN_CNT_INITIALIZED_DATA
  || section_has_characteristic section_header IMAGE_SCN_CNT_UNINITIALIZED_DATA

let section_is_discardable section_header =
  section_has_characteristic section_header IMAGE_SCN_MEM_DISCARDABLE

let section_contents (buf : Buffer.t) (sh : section_header) : Buffer.t =
  let open Unsigned in
  let offset = UInt32.to_int sh.pointer_to_raw_data in
  let size = UInt32.to_int sh.size_of_raw_data in
  Bigarray.Array1.sub buf offset size

(* Find the section whose virtual address range contains [rva]. *)
let section_at_rva sections rva =
  let open Unsigned in
  Array.find_opt
    (fun (sh : section_header) ->
      let sec_rva = UInt32.to_int sh.virtual_address in
      let sec_size = UInt32.to_int sh.virtual_size in
      rva >= sec_rva && rva < sec_rva + sec_size)
    sections

(* Translate an image-relative virtual address to a file offset, if [rva]
   falls within a section. *)
let rva_to_offset sections rva =
  match section_at_rva sections rva with
  | None -> None
  | Some (sh : section_header) ->
      let sec_rva = Unsigned.UInt32.to_int sh.virtual_address in
      Some (Unsigned.UInt32.to_int sh.pointer_to_raw_data + rva - sec_rva)

(* A cursor at the file offset of [rva], if it falls within a section. *)
let cursor_at_rva buf sections rva =
  match rva_to_offset sections rva with
  | Some offset -> Some (Buffer.cursor ~at:offset buf)
  | None -> None

(* The NUL-terminated string at [rva], or "" if it is unreadable. *)
let string_at_rva buf sections rva =
  match cursor_at_rva buf sections rva with
  | Some c -> (
      match Buffer.Read.zero_string c () with Some s -> s | None -> "")
  | None -> ""

(** {2 Exports}

    A PE image's export table (the IMAGE_DIRECTORY_ENTRY_EXPORT data directory,
    typically in .edata) lists the symbols the image exposes to others. *)

type export = {
  export_ordinal : int;
  export_name : string option;
      (* None for exports referenced only by ordinal. *)
  export_address_rva : u32; (* RVA of the export, or of a forwarder string. *)
}

type export_directory = {
  dll_name : string;
  export_time_date_stamp : u32;
  export_major_version : u16;
  export_minor_version : u16;
  ordinal_base : int;
  exports : export array;
}

let read_exports buf pe_obj =
  let open Buffer.Read in
  let sections = pe_obj.section_headers in
  let cursor_at rva = cursor_at_rva buf sections rva in
  let u32_array rva n =
    match cursor_at rva with
    | None -> [||]
    | Some c ->
        (* Bounds-check before allocating, so a bogus count fails cleanly rather
           than over-allocating or reading past the buffer. *)
        Buffer.ensure c (n * 4) "Export table";
        Array.init n (fun _ -> u32 c)
  in
  let string_at rva = string_at_rva buf sections rva in
  match pe_obj.optional_header with
  | None -> None
  | Some opt -> (
      match opt.data_directory.export_table with
      | None -> None
      | Some dd -> (
          match cursor_at (Unsigned.UInt32.to_int dd.virtual_address) with
          | None -> None
          | Some cursor ->
              Buffer.ensure cursor 40 "Export directory";
              ignore (u32 cursor) (* export flags: reserved, must be 0 *);
              let time_date_stamp = u32 cursor in
              let major_version = u16 cursor in
              let minor_version = u16 cursor in
              let name_rva = Unsigned.UInt32.to_int (u32 cursor) in
              let ordinal_base = Unsigned.UInt32.to_int (u32 cursor) in
              let num_addresses = Unsigned.UInt32.to_int (u32 cursor) in
              let num_names = Unsigned.UInt32.to_int (u32 cursor) in
              let eat_rva = Unsigned.UInt32.to_int (u32 cursor) in
              let name_ptr_rva = Unsigned.UInt32.to_int (u32 cursor) in
              let ordinal_rva = Unsigned.UInt32.to_int (u32 cursor) in
              let addresses = u32_array eat_rva num_addresses in
              let name_ptrs = u32_array name_ptr_rva num_names in
              let ordinals =
                match cursor_at ordinal_rva with
                | None -> [||]
                | Some c ->
                    Buffer.ensure c (num_names * 2) "Export ordinal table";
                    Array.init num_names (fun _ -> u16 c)
              in
              (* Attach each name to its export-address-table slot. *)
              let names = Array.make (Array.length addresses) None in
              Array.iteri
                (fun j ptr ->
                  if j < Array.length ordinals then
                    let idx = Unsigned.UInt16.to_int ordinals.(j) in
                    if idx < Array.length names then
                      match cursor_at (Unsigned.UInt32.to_int ptr) with
                      | Some c -> names.(idx) <- zero_string c ()
                      | None -> ())
                name_ptrs;
              let entries = ref [] in
              Array.iteri
                (fun i addr ->
                  if Unsigned.UInt32.to_int addr <> 0 then
                    entries :=
                      {
                        export_ordinal = ordinal_base + i;
                        export_name = names.(i);
                        export_address_rva = addr;
                      }
                      :: !entries)
                addresses;
              Some
                {
                  dll_name = string_at name_rva;
                  export_time_date_stamp = time_date_stamp;
                  export_major_version = major_version;
                  export_minor_version = minor_version;
                  ordinal_base;
                  exports = Array.of_list (List.rev !entries);
                }))

(** {2 Imports}

    A PE image's import table (the IMAGE_DIRECTORY_ENTRY_IMPORT data directory,
    typically in .idata) is a list of descriptors, one per imported DLL, each
    naming the symbols imported from it by name (with a hint) or by ordinal. *)

type imported_symbol =
  | Import_by_name of { hint : int; name : string }
  | Import_by_ordinal of int

type import_descriptor = {
  import_dll_name : string;
  imports : imported_symbol list;
}

let read_imports buf pe_obj =
  let open Buffer.Read in
  let sections = pe_obj.section_headers in
  let cursor_at rva = cursor_at_rva buf sections rva in
  let string_at rva = string_at_rva buf sections rva in
  match pe_obj.optional_header with
  | None -> [||]
  | Some opt -> (
      match opt.data_directory.import_table with
      | None -> [||]
      | Some dd -> (
          match cursor_at (Unsigned.UInt32.to_int dd.virtual_address) with
          | None -> [||]
          | Some cursor ->
              let pe32plus = opt.magic = PE32PLUS in
              (* One import-lookup-table entry: a terminating zero, an ordinal
                 (top bit set), or an RVA to a hint/name entry. *)
              let read_thunk c =
                Buffer.ensure c (if pe32plus then 8 else 4) "Import thunk";
                if pe32plus then
                  let v = u64 c in
                  if Unsigned.UInt64.(equal v zero) then `End
                  else if
                    not
                      Unsigned.UInt64.(
                        equal (logand v (shift_left one 63)) zero)
                  then
                    `Ordinal Unsigned.UInt64.(to_int (logand v (of_int 0xffff)))
                  else
                    `Name_rva
                      Unsigned.UInt64.(to_int (logand v (of_int 0x7fffffff)))
                else
                  let v = Unsigned.UInt32.to_int (u32 c) in
                  if v = 0 then `End
                  else if v land 0x80000000 <> 0 then `Ordinal (v land 0xffff)
                  else `Name_rva v
              in
              let hint_name rva =
                match cursor_at rva with
                | None -> (0, "")
                | Some c ->
                    Buffer.ensure c 2 "Import hint/name";
                    let hint = Unsigned.UInt16.to_int (u16 c) in
                    let name =
                      match zero_string c () with Some s -> s | None -> ""
                    in
                    (hint, name)
              in
              let read_thunks thunk_rva =
                match cursor_at thunk_rva with
                | None -> []
                | Some c ->
                    let rec loop acc =
                      match read_thunk c with
                      | `End -> List.rev acc
                      | `Ordinal ord -> loop (Import_by_ordinal ord :: acc)
                      | `Name_rva rva ->
                          let hint, name = hint_name rva in
                          loop (Import_by_name { hint; name } :: acc)
                    in
                    loop []
              in
              (* Walk descriptors until the terminating all-zero entry. *)
              let rec loop acc =
                Buffer.ensure cursor 20 "Import descriptor";
                let original_first_thunk =
                  Unsigned.UInt32.to_int (u32 cursor)
                in
                ignore (u32 cursor) (* time/date stamp *);
                ignore (u32 cursor) (* forwarder chain *);
                let name_rva = Unsigned.UInt32.to_int (u32 cursor) in
                let first_thunk = Unsigned.UInt32.to_int (u32 cursor) in
                if original_first_thunk = 0 && name_rva = 0 && first_thunk = 0
                then List.rev acc
                else
                  let thunk_rva =
                    if original_first_thunk <> 0 then original_first_thunk
                    else first_thunk
                  in
                  let desc =
                    {
                      import_dll_name = string_at name_rva;
                      imports = read_thunks thunk_rva;
                    }
                  in
                  loop (desc :: acc)
              in
              Array.of_list (loop [])))

(** {2 Debug Directory}

    The debug directory is found via the IMAGE_DIRECTORY_ENTRY_DEBUG data
    directory entry. It contains entries describing debug information, including
    the path to the PDB file. *)

type debug_type =
  | IMAGE_DEBUG_TYPE_UNKNOWN
  | IMAGE_DEBUG_TYPE_COFF
  | IMAGE_DEBUG_TYPE_CODEVIEW
  | IMAGE_DEBUG_TYPE_FPO
  | IMAGE_DEBUG_TYPE_MISC
  | IMAGE_DEBUG_TYPE_EXCEPTION
  | IMAGE_DEBUG_TYPE_FIXUP
  | IMAGE_DEBUG_TYPE_BORLAND
  | IMAGE_DEBUG_TYPE_REPRO
  | IMAGE_DEBUG_TYPE_POGO
  | IMAGE_DEBUG_TYPE_ILTCG
  | IMAGE_DEBUG_TYPE_MPX
  | IMAGE_DEBUG_TYPE_OTHER of int

let debug_type_of_int = function
  | 0 -> IMAGE_DEBUG_TYPE_UNKNOWN
  | 1 -> IMAGE_DEBUG_TYPE_COFF
  | 2 -> IMAGE_DEBUG_TYPE_CODEVIEW
  | 3 -> IMAGE_DEBUG_TYPE_FPO
  | 4 -> IMAGE_DEBUG_TYPE_MISC
  | 5 -> IMAGE_DEBUG_TYPE_EXCEPTION
  | 6 -> IMAGE_DEBUG_TYPE_FIXUP
  | 9 -> IMAGE_DEBUG_TYPE_BORLAND
  | 16 -> IMAGE_DEBUG_TYPE_REPRO
  | 13 -> IMAGE_DEBUG_TYPE_POGO
  | 14 -> IMAGE_DEBUG_TYPE_ILTCG
  | 15 -> IMAGE_DEBUG_TYPE_MPX
  | n -> IMAGE_DEBUG_TYPE_OTHER n

type debug_directory_entry = {
  characteristics : u32;
  time_date_stamp : u32;
  major_version : u16;
  minor_version : u16;
  debug_type : debug_type;
  size_of_data : u32;
  address_of_raw_data : u32;
  pointer_to_raw_data : u32;
}

type codeview_info = {
  cv_signature : string;  (** "RSDS" for PDB 7.0 *)
  guid : string;  (** 16-byte GUID *)
  age : u32;  (** PDB age (revision counter), paired with [guid] to match *)
  pdb_path : string;  (** Path to the external .pdb file *)
}

let parse_debug_directory (buf : Buffer.t) (pe_obj : pe_object) :
    debug_directory_entry list =
  match pe_obj.optional_header with
  | None -> []
  | Some opt -> (
      match opt.data_directory.debug_data with
      | None -> []
      | Some dd -> (
          let rva = Unsigned.UInt32.to_int dd.virtual_address in
          let size = Unsigned.UInt32.to_int dd.size in
          if rva = 0 || size = 0 then []
          else
            match cursor_at_rva buf pe_obj.section_headers rva with
            | None -> []
            | Some cursor ->
                let entry_size = 28 in
                let count = size / entry_size in
                List.init count (fun _ ->
                    let open Buffer.Read in
                    let characteristics = u32 cursor in
                    let time_date_stamp = u32 cursor in
                    let major_version = u16 cursor in
                    let minor_version = u16 cursor in
                    let type_raw = u32 cursor |> Unsigned.UInt32.to_int in
                    let debug_type = debug_type_of_int type_raw in
                    let size_of_data = u32 cursor in
                    let address_of_raw_data = u32 cursor in
                    let pointer_to_raw_data = u32 cursor in
                    {
                      characteristics;
                      time_date_stamp;
                      major_version;
                      minor_version;
                      debug_type;
                      size_of_data;
                      address_of_raw_data;
                      pointer_to_raw_data;
                    })))

let parse_codeview_info (buf : Buffer.t) (entry : debug_directory_entry) :
    codeview_info option =
  let open Unsigned in
  let offset = UInt32.to_int entry.pointer_to_raw_data in
  let size = UInt32.to_int entry.size_of_data in
  if offset = 0 || size < 24 then None
  else
    let open Buffer.Read in
    let cursor = Buffer.cursor ~at:offset buf in
    let cv_signature = fixed_string cursor 4 in
    if cv_signature = "RSDS" then
      let guid = fixed_string cursor 16 in
      let age = u32 cursor in
      let remaining = size - 24 in
      let pdb_path = string_until_nul (fixed_string cursor remaining) in
      Some { cv_signature; guid; age; pdb_path }
    else None

let find_pdb_path (buf : Buffer.t) (pe_obj : pe_object) : string option =
  let entries = parse_debug_directory buf pe_obj in
  let codeview_entry =
    List.find_opt (fun e -> e.debug_type = IMAGE_DEBUG_TYPE_CODEVIEW) entries
  in
  match codeview_entry with
  | None -> None
  | Some entry -> (
      match parse_codeview_info buf entry with
      | Some info -> Some info.pdb_path
      | None -> None)

(** {2 Exception Data (.pdata / .xdata)} *)

type runtime_function = {
  begin_address : u32;
  end_address : u32;
  unwind_info_address : u32;
}

let parse_pdata (buf : Buffer.t) (sh : section_header) : runtime_function array
    =
  let open Unsigned in
  let offset = UInt32.to_int sh.pointer_to_raw_data in
  let size = UInt32.to_int sh.size_of_raw_data in
  let count = size / 12 in
  let cursor = Buffer.cursor ~at:offset buf in
  Array.init count (fun _ ->
      let open Buffer.Read in
      let begin_address = u32 cursor in
      let end_address = u32 cursor in
      let unwind_info_address = u32 cursor in
      { begin_address; end_address; unwind_info_address })

let write_u32_le_pe buf v =
  let open Stdlib.Buffer in
  add_char buf (Char.chr (v land 0xFF));
  add_char buf (Char.chr ((v lsr 8) land 0xFF));
  add_char buf (Char.chr ((v lsr 16) land 0xFF));
  add_char buf (Char.chr ((v lsr 24) land 0xFF))

let write_pdata (buf : Stdlib.Buffer.t) (entries : runtime_function list) : unit
    =
  List.iter
    (fun e ->
      write_u32_le_pe buf (Unsigned.UInt32.to_int e.begin_address);
      write_u32_le_pe buf (Unsigned.UInt32.to_int e.end_address);
      write_u32_le_pe buf (Unsigned.UInt32.to_int e.unwind_info_address))
    entries
