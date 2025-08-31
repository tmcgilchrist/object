(* Implementation of nm - display name list (symbol table) *)

open Object
open Cmdliner
open Printf

(* Symbol type mapping from Mach-O symbol types to nm-style letters *)
let symbol_type_to_char sym_type sym_ext =
  match sym_type with
  | `UNDF -> if sym_ext then 'U' else 'u'
  | `ABS -> if sym_ext then 'A' else 'a'
  | `SECT -> if sym_ext then 'T' else 't'
  | `PBUD -> 'P'
  | `INDR -> 'I'
  (* STAB debug symbols *)
  | `GSYM -> 'G' (* global symbol *)
  | `FNAME -> 'F' (* procedure name (f77 kludge) *)
  | `FUN -> 'f' (* procedure *)
  | `STSYM -> 'S' (* static symbol *)
  | `LCSYM -> 'L' (* .lcomm symbol *)
  | `BNSYM -> 'B' (* begin nsect sym *)
  | `OPT -> 'O' (* emitted with gcc2_compiled *)
  | `RSYM -> 'R' (* register sym *)
  | `SLINE -> 's' (* src line *)
  | `ENSYM -> 'E' (* end nsect sym *)
  | `SSYM -> 'S' (* structure elt *)
  | `SO -> 'o' (* source file name *)
  | `OSO -> 'O' (* object file name *)
  | `LSYM -> 'l' (* local sym *)
  | `BINCL -> 'b' (* include file beginning *)
  | `SOL -> 's' (* included file name *)
  | `PARAMS -> 'p' (* compiler parameters *)
  | `VERSION -> 'v' (* compiler version *)
  | `OLEVEL -> 'O' (* compiler -O level *)
  | `PSYM -> 'P' (* parameter *)
  | `EINCL -> 'e' (* include file end *)
  | `ENTRY -> 'e' (* alternate entry *)
  | `LBRAC -> '{' (* left bracket *)
  | `EXCL -> 'x' (* deleted include file *)
  | `RBRAC -> '}' (* right bracket *)
  | `BCOMM -> 'c' (* begin common *)
  | `ECOMM -> 'C' (* end common *)
  | `ECOML -> 'c' (* end common (local name) *)
  | `LENG -> 'L' (* second stab entry with length information *)
  | `PC -> 'P' (* global pascal symbol *)
  | _ -> '?'

(* Check if symbol is a STAB debug symbol *)
let is_debug_symbol sym_type =
  match sym_type with
  | `GSYM | `FNAME | `FUN | `STSYM | `LCSYM | `BNSYM | `OPT | `RSYM | `SLINE
  | `ENSYM | `SSYM | `SO | `OSO | `LSYM | `BINCL | `SOL | `PARAMS | `VERSION
  | `OLEVEL | `PSYM | `EINCL | `ENTRY | `LBRAC | `EXCL | `RBRAC | `BCOMM
  | `ECOMM | `ECOML | `LENG | `PC ->
      true
  | _ -> false

(* ELF symbol type mapping to nm-style letters *)
let elf_symbol_type_to_char sym_type sym_binding sections sym_shndx =
  let is_global =
    match sym_binding with `STB_GLOBAL | `STB_WEAK -> true | _ -> false
  in
  let shndx_int = Unsigned.UInt16.to_int sym_shndx in

  (* Handle special section indices *)
  if shndx_int = 0 then
    (* SHN_UNDEF - undefined symbol *)
    if is_global then 'U' else 'u'
  else if shndx_int = 0xfff1 then
    (* SHN_ABS - absolute symbol *)
    if is_global then 'A' else 'a'
  else if shndx_int = 0xfff2 then
    (* SHN_COMMON - common symbol *)
    'C'
  else if shndx_int < Array.length sections then
    (* Regular section - determine type by section characteristics *)
    let section = sections.(shndx_int) in
    let section_name = section.Elf.sh_name_str in
    let sh_flags = Unsigned.UInt64.to_int section.Elf.sh_flags in
    let has_exec = sh_flags land 0x4 != 0 in
    (* SHF_EXECINSTR *)
    let has_write = sh_flags land 0x1 != 0 in
    (* SHF_WRITE *)
    let has_alloc = sh_flags land 0x2 != 0 in
    (* SHF_ALLOC *)

    match sym_type with
    | `STT_FILE -> 'f' (* File symbol *)
    | `STT_SECTION -> if is_global then 'N' else 'n' (* Section symbol *)
    | `STT_FUNC when has_exec -> if is_global then 'T' else 't' (* Text *)
    | `STT_OBJECT when has_write && has_alloc ->
        if is_global then 'D' else 'd' (* Data *)
    | `STT_OBJECT when (not has_write) && has_alloc ->
        if is_global then 'R' else 'r' (* Read-only data *)
    | `STT_OBJECT -> if is_global then 'D' else 'd' (* Default to data *)
    | `STT_NOTYPE when has_exec -> if is_global then 'T' else 't' (* Code *)
    | `STT_NOTYPE when has_write && has_alloc ->
        if is_global then 'D' else 'd' (* Data *)
    | `STT_NOTYPE when (not has_write) && has_alloc ->
        if is_global then 'R' else 'r' (* Read-only *)
    | `STT_NOTYPE
      when String.length section_name >= 4
           && String.sub section_name 0 4 = ".bss" ->
        if is_global then 'B' else 'b' (* BSS *)
    | `STT_TLS -> if is_global then 'T' else 't' (* Thread-local *)
    | `STT_COMMON -> 'C' (* Common *)
    | _ -> if is_global then 'D' else 'd' (* Default to data *)
  else
    (* Invalid section index *)
    '?'

(* Check if ELF symbol should be filtered (for -a flag) *)
let is_elf_debug_symbol _sym_type =
  false (* ELF doesn't have STAB debug symbols like Mach-O *)

(* Filter symbols based on flags *)
let filter_symbols symbols show_all =
  if show_all then symbols
  else List.filter (fun sym -> not (is_debug_symbol sym.Macho.sym_type)) symbols

(* Format symbol address - show spaces for undefined symbols *)
let format_address value sym_type =
  match sym_type with
  | `UNDF -> "                " (* 16 spaces for undefined symbols *)
  | _ -> sprintf "%016Lx" (Unsigned.UInt64.to_int64 value)

(* Format ELF symbol address *)
let format_elf_address value sym_shndx =
  if Unsigned.UInt16.to_int sym_shndx = 0 then "                "
    (* 16 spaces for undefined symbols *)
  else sprintf "%016Lx" (Unsigned.UInt64.to_int64 value)

(* Process a single symbol and format it for output *)
let format_symbol symbol =
  let addr_str = format_address symbol.Macho.sym_value symbol.Macho.sym_type in
  let type_char =
    symbol_type_to_char symbol.Macho.sym_type symbol.Macho.sym_ext
  in
  sprintf "%s %c %s" addr_str type_char symbol.Macho.sym_name

(* Process a single ELF symbol and format it for output *)
let format_elf_symbol sections symbol =
  let addr_str = format_elf_address symbol.Elf.st_value symbol.Elf.st_shndx in
  let type_char =
    elf_symbol_type_to_char symbol.Elf.st_type symbol.Elf.st_binding sections
      symbol.Elf.st_shndx
  in
  sprintf "%s %c %s" addr_str type_char symbol.Elf.st_name_str

(* Compare symbols for sorting - defined symbols by address, undefined at end *)
let compare_symbols s1 s2 =
  match (s1.Macho.sym_type, s2.Macho.sym_type) with
  | `UNDF, `UNDF -> String.compare s1.Macho.sym_name s2.Macho.sym_name
  | `UNDF, _ -> 1 (* undefined symbols go last *)
  | _, `UNDF -> -1 (* undefined symbols go last *)
  | _, _ ->
      let addr_cmp =
        Unsigned.UInt64.compare s1.Macho.sym_value s2.Macho.sym_value
      in
      if addr_cmp = 0 then String.compare s1.Macho.sym_name s2.Macho.sym_name
      else addr_cmp

(* Compare ELF symbols for sorting *)
let compare_elf_symbols s1 s2 =
  let s1_undefined = Unsigned.UInt16.to_int s1.Elf.st_shndx = 0 in
  let s2_undefined = Unsigned.UInt16.to_int s2.Elf.st_shndx = 0 in
  match (s1_undefined, s2_undefined) with
  | true, true -> String.compare s1.Elf.st_name_str s2.Elf.st_name_str
  | true, false -> 1 (* undefined symbols go last *)
  | false, true -> -1 (* undefined symbols go last *)
  | false, false ->
      let addr_cmp = Unsigned.UInt64.compare s1.Elf.st_value s2.Elf.st_value in
      if addr_cmp = 0 then String.compare s1.Elf.st_name_str s2.Elf.st_name_str
      else addr_cmp

(* Filter ELF symbols based on flags *)
let filter_elf_symbols symbols show_all =
  if show_all then symbols
  else
    List.filter (fun sym -> not (is_elf_debug_symbol sym.Elf.st_type)) symbols

(* Process Mach-O file and extract symbols *)
let process_macho_file filename show_all preserve_order =
  try
    let buffer = Buffer.parse filename in
    let _header, commands = Macho.read buffer in

    (* Extract symbols from LC_SYMTAB commands *)
    let symbols = ref [] in
    List.iter
      (function
        | Macho.LC_SYMTAB (lazy (symbol_array, _)) ->
            symbols := Array.to_list symbol_array @ !symbols
        | _ -> ())
      commands;

    (* Filter symbols based on -a flag *)
    let filtered_symbols = filter_symbols !symbols show_all in

    (* Sort symbols unless -p flag is used *)
    let final_symbols =
      if preserve_order then filtered_symbols
      else List.sort compare_symbols filtered_symbols
    in

    List.iter (fun sym -> print_endline (format_symbol sym)) final_symbols
  with
  | Sys_error msg ->
      eprintf "nm: %s: %s\n" filename msg;
      exit 1
  | Buffer.Invalid_format msg ->
      eprintf "nm: %s: %s\n" filename msg;
      exit 1

(* Process ELF file and extract symbols *)
let process_elf_file filename show_all preserve_order =
  try
    let buffer = Buffer.parse filename in
    let header, sections = Elf.read_elf buffer in
    let symbols = Elf.read_symbol_table buffer header sections in

    (* Filter symbols based on -a flag *)
    let symbol_list = Array.to_list symbols in
    let filtered_symbols = filter_elf_symbols symbol_list show_all in

    (* Sort symbols unless -p flag is used *)
    let final_symbols =
      if preserve_order then filtered_symbols
      else List.sort compare_elf_symbols filtered_symbols
    in

    List.iter
      (fun sym -> print_endline (format_elf_symbol sections sym))
      final_symbols
  with
  | Sys_error msg ->
      eprintf "nm: %s: %s\n" filename msg;
      exit 1
  | Buffer.Invalid_format msg ->
      eprintf "nm: %s: %s\n" filename msg;
      exit 1

(* Process file based on detected format *)
let process_file filename show_all preserve_order =
  try
    let buffer = Buffer.parse filename in
    let obj = Object_format.read buffer in
    match Object_format.format obj with
    | Object_format.MACHO -> process_macho_file filename show_all preserve_order
    | Object_format.ELF -> process_elf_file filename show_all preserve_order
  with
  | Sys_error msg ->
      eprintf "nm: %s: %s\n" filename msg;
      exit 1
  | Buffer.Invalid_format msg ->
      eprintf "nm: %s: %s\n" filename msg;
      exit 1
  | Failure msg ->
      eprintf "nm: %s: %s\n" filename msg;
      exit 1
  | exn ->
      eprintf "nm: %s: Unexpected error: %s\n" filename (Printexc.to_string exn);
      exit 1

(* Command line interface *)
let filename =
  let doc = "Object file to examine" in
  Arg.(required & pos 0 (some file) None & info [] ~docv:"FILE" ~doc)

let show_all_flag =
  let doc =
    "Display all symbol table entries, including those inserted for use by \
     debuggers"
  in
  Arg.(value & flag & info [ "a" ] ~doc)

let preserve_order_flag =
  let doc = "Do not sort, display symbols in symbol-table order" in
  Arg.(value & flag & info [ "p" ] ~doc)

let cmd =
  let doc = "display name list (symbol table)" in
  let info = Cmd.info "nm" ~doc in
  Cmd.v info
    Term.(const process_file $ filename $ show_all_flag $ preserve_order_flag)

let () = exit (Cmd.eval cmd)
