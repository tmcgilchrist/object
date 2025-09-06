open Types

(** Windows PE/COFF parser based on
    {:https://docs.microsoft.com/en-us/windows/win32/debug/pe-format}. *)

(** Prior art for PE/COFF parsers:
    https://github.com/ocaml/ocaml/blob/trunk/utils/binutils.ml#L480
    https://github.com/ocaml/flexdll/blob/master/coff.ml *)

type machine_type =
  [ `IMAGE_FILE_MACHINE_I386
  | `IMAGE_FILE_MACHINE_AMD64
  | `IMAGE_FILE_MACHINE_ARM
  | `IMAGE_FILE_MACHINE_ARM64
  | `IMAGE_FILE_MACHINE_UNKNOWN of u16 ]

type pe_magic = PE32 | PE32PLUS

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

type coff_header = {
  machine : machine_type;
  number_of_sections : u16;
  time_date_stamp : u32;
  pointer_to_symbol_table : u32;
  number_of_symbols : u32;
  size_of_optional_header : u16;
  characteristics : u16;
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

and data_directory_type =
  [ `IMAGE_DIRECTORY_ENTRY_EXPORT
  | `IMAGE_DIRECTORY_ENTRY_IMPORT
  | `IMAGE_DIRECTORY_ENTRY_RESOURCE
  | `IMAGE_DIRECTORY_ENTRY_EXCEPTION
  | `IMAGE_DIRECTORY_ENTRY_SECURITY
  | `IMAGE_DIRECTORY_ENTRY_BASERELOC
  | `IMAGE_DIRECTORY_ENTRY_DEBUG
  | `IMAGE_DIRECTORY_ENTRY_ARCHITECTURE
  | `IMAGE_DIRECTORY_ENTRY_GLOBALPTR
  | `IMAGE_DIRECTORY_ENTRY_TLS
  | `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
  | `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
  | `IMAGE_DIRECTORY_ENTRY_IAT
  | `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
  | `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
  | `IMAGE_DIRECTORY_ENTRY_RESERVED
  ]

and data_directory_entry = {
  virtual_address : u32;
  size : u32;
}

and data_directory = {
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
  let open Unsigned.UInt16 in
  match to_int n with
  | 0x014c -> `IMAGE_FILE_MACHINE_I386
  | 0x8664 -> `IMAGE_FILE_MACHINE_AMD64
  | 0x01c0 -> `IMAGE_FILE_MACHINE_ARM
  | 0xaa64 -> `IMAGE_FILE_MACHINE_ARM64
  | _ -> `IMAGE_FILE_MACHINE_UNKNOWN n

let pe_magic_of_u16 = function
  | 0x10b -> PE32
  | 0x20b -> PE32PLUS
  | n -> Buffer.invalid_format (Printf.sprintf "Unknown PE magic: 0x%x" n)

let section_characteristics_of_u32 flags =
  let open Unsigned.UInt32 in
  let flags_int = to_int flags in
  let characteristics = [] in
  let characteristics =
    if flags_int land 0x00000008 <> 0 then
      `IMAGE_SCN_TYPE_NO_PAD :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x00000020 <> 0 then
      `IMAGE_SCN_CNT_CODE :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x00000040 <> 0 then
      `IMAGE_SCN_CNT_INITIALIZED_DATA :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x00000080 <> 0 then
      `IMAGE_SCN_CNT_UNINITIALIZED_DATA :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x00000200 <> 0 then
      `IMAGE_SCN_LNK_INFO :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x00000800 <> 0 then
      `IMAGE_SCN_LNK_REMOVE :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x00001000 <> 0 then
      `IMAGE_SCN_LNK_COMDAT :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x02000000 <> 0 then
      `IMAGE_SCN_MEM_DISCARDABLE :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x04000000 <> 0 then
      `IMAGE_SCN_MEM_NOT_CACHED :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x08000000 <> 0 then
      `IMAGE_SCN_MEM_NOT_PAGED :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x10000000 <> 0 then
      `IMAGE_SCN_MEM_SHARED :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x20000000 <> 0 then
      `IMAGE_SCN_MEM_EXECUTE :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x40000000 <> 0 then
      `IMAGE_SCN_MEM_READ :: characteristics
    else characteristics
  in
  let characteristics =
    if flags_int land 0x80000000 <> 0 then
      `IMAGE_SCN_MEM_WRITE :: characteristics
    else characteristics
  in
  if characteristics = [] then [ `IMAGE_SCN_UNKNOWN flags ] else characteristics

let is_pe buffer =
  try
    let cursor = Buffer.cursor buffer in
    Buffer.ensure cursor 2 "PE detection: insufficient data for DOS signature";
    let dos_signature = Buffer.Read.u16 cursor in
    if dos_signature <> Unsigned.UInt16.of_int 0x5a4d then false
    else (
      Buffer.ensure cursor 58 "PE detection: insufficient data for DOS header";
      Buffer.seek cursor 60;
      let pe_header_offset = Buffer.Read.u32 cursor in
      let pe_offset = Unsigned.UInt32.to_int pe_header_offset in
      Buffer.ensure cursor (pe_offset + 4)
        "PE detection: insufficient data for PE signature";
      Buffer.seek cursor pe_offset;
      let pe_signature = Buffer.Read.u32 cursor in
      pe_signature = Unsigned.UInt32.of_int 0x00004550)
  with Buffer.Invalid_format _ -> false

let find_pe_header_offset buffer =
  let cursor = Buffer.cursor buffer in
  Buffer.ensure cursor 2 "DOS signature check";
  let dos_signature = Buffer.Read.u16 cursor in
  if dos_signature <> Unsigned.UInt16.of_int 0x5a4d then
    Buffer.invalid_format "Not a DOS/PE file: missing DOS signature";
  Buffer.seek cursor 60;
  let pe_header_offset = Buffer.Read.u32 cursor in
  Unsigned.UInt32.to_int pe_header_offset

let read_coff_header cursor =
  Buffer.ensure cursor 24 "COFF header";
  let pe_signature = Buffer.Read.u32 cursor in
  if pe_signature <> Unsigned.UInt32.of_int 0x00004550 then
    Buffer.invalid_format "Not a PE file: missing PE signature";
  let machine = machine_type_of_u16 (Buffer.Read.u16 cursor) in
  let number_of_sections = Buffer.Read.u16 cursor in
  let time_date_stamp = Buffer.Read.u32 cursor in
  let pointer_to_symbol_table = Buffer.Read.u32 cursor in
  let number_of_symbols = Buffer.Read.u32 cursor in
  let size_of_optional_header = Buffer.Read.u16 cursor in
  let characteristics = Buffer.Read.u16 cursor in
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
  let virtual_address = Buffer.Read.u32 cursor in
  let size = Buffer.Read.u32 cursor in
  if Unsigned.UInt32.to_int virtual_address = 0 && Unsigned.UInt32.to_int size = 0 then
    None
  else
    Some { virtual_address; size }

let read_data_directory cursor num_entries =
  let entries = Array.make 16 None in
  for i = 0 to min (Unsigned.UInt32.to_int num_entries - 1) 15 do
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
  | `IMAGE_DIRECTORY_ENTRY_EXPORT -> data_directory.export_table
  | `IMAGE_DIRECTORY_ENTRY_IMPORT -> data_directory.import_table
  | `IMAGE_DIRECTORY_ENTRY_RESOURCE -> data_directory.resource_table
  | `IMAGE_DIRECTORY_ENTRY_EXCEPTION -> data_directory.exception_table
  | `IMAGE_DIRECTORY_ENTRY_SECURITY -> data_directory.certificate_table
  | `IMAGE_DIRECTORY_ENTRY_BASERELOC -> data_directory.base_relocation_table
  | `IMAGE_DIRECTORY_ENTRY_DEBUG -> data_directory.debug_data
  | `IMAGE_DIRECTORY_ENTRY_ARCHITECTURE -> data_directory.architecture_data
  | `IMAGE_DIRECTORY_ENTRY_GLOBALPTR -> data_directory.global_ptr
  | `IMAGE_DIRECTORY_ENTRY_TLS -> data_directory.tls_table
  | `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG -> data_directory.load_config_table
  | `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT -> data_directory.bound_import_table
  | `IMAGE_DIRECTORY_ENTRY_IAT -> data_directory.import_address_table
  | `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT -> data_directory.delay_import_table
  | `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR -> data_directory.com_descriptor
  | `IMAGE_DIRECTORY_ENTRY_RESERVED -> data_directory.reserved

let has_data_directory data_directory dir_type =
  match get_data_directory_entry data_directory dir_type with
  | Some entry -> Unsigned.UInt32.to_int entry.virtual_address <> 0 || Unsigned.UInt32.to_int entry.size <> 0
  | None -> false

let get_data_directory_address data_directory dir_type =
  match get_data_directory_entry data_directory dir_type with
  | Some entry -> Some entry.virtual_address
  | None -> None

let get_data_directory_size data_directory dir_type =
  match get_data_directory_entry data_directory dir_type with
  | Some entry -> Some entry.size
  | None -> None

let read_optional_header cursor optional_header_size =
  if Unsigned.UInt16.to_int optional_header_size < 24 then
    Buffer.invalid_format "Optional header too small";

  Buffer.ensure cursor 24 "Optional header standard fields";
  let magic =
    pe_magic_of_u16 (Unsigned.UInt16.to_int (Buffer.Read.u16 cursor))
  in
  let major_linker_version = Buffer.Read.u8 cursor in
  let minor_linker_version = Buffer.Read.u8 cursor in
  let size_of_code = Buffer.Read.u32 cursor in
  let size_of_initialized_data = Buffer.Read.u32 cursor in
  let size_of_uninitialized_data = Buffer.Read.u32 cursor in
  let address_of_entry_point = Buffer.Read.u32 cursor in
  let base_of_code = Buffer.Read.u32 cursor in

  let base_of_data, image_base =
    match magic with
    | PE32 ->
        Buffer.ensure cursor 8 "PE32 additional fields";
        let base_of_data = Some (Buffer.Read.u32 cursor) in
        let image_base =
          Unsigned.UInt64.of_int
            (Unsigned.UInt32.to_int (Buffer.Read.u32 cursor))
        in
        (base_of_data, image_base)
    | PE32PLUS ->
        Buffer.ensure cursor 8 "PE32+ image base";
        let image_base = Buffer.Read.u64 cursor in
        (None, image_base)
  in

  Buffer.ensure cursor 68 "Optional header Windows fields";
  let section_alignment = Buffer.Read.u32 cursor in
  let file_alignment = Buffer.Read.u32 cursor in
  let major_operating_system_version = Buffer.Read.u16 cursor in
  let minor_operating_system_version = Buffer.Read.u16 cursor in
  let major_image_version = Buffer.Read.u16 cursor in
  let minor_image_version = Buffer.Read.u16 cursor in
  let major_subsystem_version = Buffer.Read.u16 cursor in
  let minor_subsystem_version = Buffer.Read.u16 cursor in
  let win32_version_value = Buffer.Read.u32 cursor in
  let size_of_image = Buffer.Read.u32 cursor in
  let size_of_headers = Buffer.Read.u32 cursor in
  let checksum = Buffer.Read.u32 cursor in
  let subsystem = Buffer.Read.u16 cursor in
  let dll_characteristics = Buffer.Read.u16 cursor in

  let ( size_of_stack_reserve,
        size_of_stack_commit,
        size_of_heap_reserve,
        size_of_heap_commit ) =
    match magic with
    | PE32 ->
        Buffer.ensure cursor 16 "PE32 size fields";
        let stack_reserve =
          Unsigned.UInt64.of_int
            (Unsigned.UInt32.to_int (Buffer.Read.u32 cursor))
        in
        let stack_commit =
          Unsigned.UInt64.of_int
            (Unsigned.UInt32.to_int (Buffer.Read.u32 cursor))
        in
        let heap_reserve =
          Unsigned.UInt64.of_int
            (Unsigned.UInt32.to_int (Buffer.Read.u32 cursor))
        in
        let heap_commit =
          Unsigned.UInt64.of_int
            (Unsigned.UInt32.to_int (Buffer.Read.u32 cursor))
        in
        (stack_reserve, stack_commit, heap_reserve, heap_commit)
    | PE32PLUS ->
        Buffer.ensure cursor 32 "PE32+ size fields";
        let stack_reserve = Buffer.Read.u64 cursor in
        let stack_commit = Buffer.Read.u64 cursor in
        let heap_reserve = Buffer.Read.u64 cursor in
        let heap_commit = Buffer.Read.u64 cursor in
        (stack_reserve, stack_commit, heap_reserve, heap_commit)
  in

  Buffer.ensure cursor 8 "Optional header final fields";
  let loader_flags = Buffer.Read.u32 cursor in
  let number_of_rva_and_sizes = Buffer.Read.u32 cursor in

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

let read_section_header cursor =
  Buffer.ensure cursor 40 "Section header";
  let name_bytes = Buffer.Read.fixed_string cursor 8 in
  let name =
    if
      String.length name_bytes = 0
      || String.for_all (fun c -> c = '\000') name_bytes
    then "" (* Empty name - will be handled by caller *)
    else
      (* Find the end of the string (before first null byte) *)
      let len = String.length name_bytes in
      let rec find_null pos =
        if pos >= len then len
        else if name_bytes.[pos] = '\000' then pos
        else find_null (pos + 1)
      in
      let name_len = find_null 0 in
      if name_len = 0 then "" else String.sub name_bytes 0 name_len
  in
  let virtual_size = Buffer.Read.u32 cursor in
  let virtual_address = Buffer.Read.u32 cursor in
  let size_of_raw_data = Buffer.Read.u32 cursor in
  let pointer_to_raw_data = Buffer.Read.u32 cursor in
  let pointer_to_relocations = Buffer.Read.u32 cursor in
  let pointer_to_line_numbers = Buffer.Read.u32 cursor in
  let number_of_relocations = Buffer.Read.u16 cursor in
  let number_of_line_numbers = Buffer.Read.u16 cursor in
  let characteristics_raw = Buffer.Read.u32 cursor in
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

let read_section_headers cursor number_of_sections =
  Array.init (Unsigned.UInt16.to_int number_of_sections) (fun _ ->
      read_section_header cursor)

let machine_to_arch = function
  | `IMAGE_FILE_MACHINE_I386 -> `X86
  | `IMAGE_FILE_MACHINE_AMD64 -> `X86_64
  | `IMAGE_FILE_MACHINE_ARM -> `ARM
  | `IMAGE_FILE_MACHINE_ARM64 -> `ARM64
  | `IMAGE_FILE_MACHINE_UNKNOWN n -> `Unknown (Unsigned.UInt16.to_int n)

let section_characteristics_to_type_string characteristics =
  let has_char char = List.mem char characteristics in
  if has_char `IMAGE_SCN_CNT_CODE then "CODE"
  else if has_char `IMAGE_SCN_CNT_INITIALIZED_DATA then "DATA"
  else if has_char `IMAGE_SCN_CNT_UNINITIALIZED_DATA then "BSS"
  else if has_char `IMAGE_SCN_LNK_INFO then "INFO"
  else if has_char `IMAGE_SCN_LNK_REMOVE then "REMOVE"
  else if has_char `IMAGE_SCN_LNK_COMDAT then "COMDAT"
  else "UNKNOWN"

type pe_object = {
  coff_header : coff_header;
  optional_header : optional_header option;
  section_headers : section_header array;
}

let read buffer =
  let pe_offset = find_pe_header_offset buffer in
  let cursor = Buffer.cursor ~at:pe_offset buffer in
  let coff_header = read_coff_header cursor in
  let optional_header =
    if Unsigned.UInt16.to_int coff_header.size_of_optional_header > 0 then
      Some (read_optional_header cursor coff_header.size_of_optional_header)
    else None
  in
  let section_headers =
    read_section_headers cursor coff_header.number_of_sections
  in
  { coff_header; optional_header; section_headers }

let sections pe_obj = pe_obj.section_headers
let get_architecture pe_obj = machine_to_arch pe_obj.coff_header.machine

let is_64bit pe_obj =
  match pe_obj.optional_header with
  | Some opt -> opt.magic = PE32PLUS
  | None -> false

let is_executable pe_obj =
  Unsigned.UInt16.to_int pe_obj.coff_header.characteristics land 0x2 <> 0

let entry_point pe_obj =
  match pe_obj.optional_header with
  | Some opt when Unsigned.UInt32.to_int opt.address_of_entry_point <> 0 ->
      Some
        (Unsigned.UInt64.of_int
           (Unsigned.UInt32.to_int opt.address_of_entry_point))
  | _ -> None

let section_has_characteristic section_header characteristic =
  List.mem characteristic section_header.characteristics

let section_is_executable section_header =
  section_has_characteristic section_header `IMAGE_SCN_MEM_EXECUTE

let section_is_writable section_header =
  section_has_characteristic section_header `IMAGE_SCN_MEM_WRITE

let section_is_readable section_header =
  section_has_characteristic section_header `IMAGE_SCN_MEM_READ

let section_contains_code section_header =
  section_has_characteristic section_header `IMAGE_SCN_CNT_CODE

let section_contains_data section_header =
  section_has_characteristic section_header `IMAGE_SCN_CNT_INITIALIZED_DATA
  || section_has_characteristic section_header `IMAGE_SCN_CNT_UNINITIALIZED_DATA

let section_is_discardable section_header =
  section_has_characteristic section_header `IMAGE_SCN_MEM_DISCARDABLE
