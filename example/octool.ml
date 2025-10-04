(* OCaml implementation of otool for MachO binaries. *)

open Object
open Cmdliner

let print_cmd_header ?(width = 8) cmd cmdsize =
  Format.printf "%*s %s@." width "cmd" cmd;
  Format.printf "%*s %d@." width "cmdsize" cmdsize

let print_fat_header filename buffer =
  if not (Macho.is_fat buffer) then
    Printf.printf "%s is not a fat file\n" filename
  else
    let fat_header = Macho.read_fat buffer in
    let nfat_arch = Array.length fat_header.fat_archs in
    Printf.printf "Fat headers\n";
    Printf.printf "fat_magic 0x%x\n"
      (Macho.fat_magic_to_int fat_header.fat_magic);
    Printf.printf "nfat_arch %d\n" nfat_arch;
    Array.iteri
      (fun i arch ->
        Printf.printf "architecture %d\n" i;
        match arch with
        | `Fat_arch fa ->
            let cputype_int = Macho.cpu_type_to_int fa.Macho.fa_cputype in
            let cpusubtype_val =
              match fa.Macho.fa_cpusubtype with
              | `Unknown n -> n
              | subtype -> Macho.cpu_subtype_to_int fa.Macho.fa_cputype subtype
            in
            let cpusubtype_int = cpusubtype_val land 0x00ffffff in
            let capabilities = (cpusubtype_val lsr 24) land 0xff in
            Printf.printf "    cputype %d\n" cputype_int;
            Printf.printf "    cpusubtype %d\n" cpusubtype_int;
            Printf.printf "    capabilities 0x%x\n" capabilities;
            Printf.printf "    offset %d\n"
              (Unsigned.UInt32.to_int fa.Macho.fa_offset);
            Printf.printf "    size %d\n"
              (Unsigned.UInt32.to_int fa.Macho.fa_size);
            Printf.printf "    align 2^%d (%d)\n"
              (Unsigned.UInt32.to_int fa.Macho.fa_align)
              (1 lsl Unsigned.UInt32.to_int fa.Macho.fa_align)
        | `Fat_arch_64 fa64 ->
            let cputype_int = Macho.cpu_type_to_int fa64.Macho.fa64_cputype in
            let cpusubtype_val =
              match fa64.Macho.fa64_cpusubtype with
              | `Unknown n -> n
              | subtype ->
                  Macho.cpu_subtype_to_int fa64.Macho.fa64_cputype subtype
            in
            let cpusubtype_int = cpusubtype_val land 0x00ffffff in
            let capabilities = (cpusubtype_val lsr 24) land 0xff in
            Printf.printf "    cputype %d\n" cputype_int;
            Printf.printf "    cpusubtype %d\n" cpusubtype_int;
            Printf.printf "    capabilities 0x%x\n" capabilities;
            Printf.printf "    offset %Ld\n"
              (Unsigned.UInt64.to_int64 fa64.Macho.fa64_offset);
            Printf.printf "    size %Ld\n"
              (Unsigned.UInt64.to_int64 fa64.Macho.fa64_size);
            Printf.printf "    align 2^%d (%d)\n"
              (Unsigned.UInt32.to_int fa64.Macho.fa64_align)
              (1 lsl Unsigned.UInt32.to_int fa64.Macho.fa64_align))
      fat_header.fat_archs

(* Consult Config.architecture from compiler-libs for this value instead? *)
let get_native_arch () =
  let ic = Unix.open_process_in "arch" in
  let arch_str = input_line ic in
  let _ = Unix.close_process_in ic in
  arch_str

(* Load command printing functions *)
let format_version v =
  let major = Unsigned.UInt32.to_int v lsr 16 in
  let minor = (Unsigned.UInt32.to_int v lsr 8) land 0xff in
  let patch = Unsigned.UInt32.to_int v land 0xff in
  Format.sprintf "%d.%d.%d" major minor patch

let sec_flags sec =
  Macho.sec_type_to_int sec.Macho.sec_type
  lor Macho.sec_user_attrs_to_int sec.Macho.sec_user_attrs
  lor Macho.sec_sys_attrs_to_int sec.Macho.sec_sys_attrs

let print_section sec =
  Printf.printf "Section\n";
  Printf.printf "  sectname %s\n" sec.Macho.sec_sectname;
  Printf.printf "   segname %s\n" sec.Macho.sec_segname;
  Printf.printf "      addr 0x%016Lx\n"
    (Unsigned.UInt64.to_int64 sec.Macho.sec_addr);
  Printf.printf "      size 0x%016Lx\n"
    (Unsigned.UInt64.to_int64 sec.Macho.sec_size);
  Printf.printf "    offset %d\n" (Unsigned.UInt32.to_int sec.Macho.sec_offset);
  let align_power =
    int_of_float (log (float_of_int sec.Macho.sec_align) /. log 2.0)
  in
  Printf.printf "     align 2^%d (%d)\n" align_power sec.Macho.sec_align;
  Printf.printf "    reloff %d\n" 0;
  Printf.printf "    nreloc %d\n" (Array.length sec.Macho.sec_relocs);
  Printf.printf "     flags 0x%08x\n" (sec_flags sec);
  let reserved1_val = Unsigned.UInt32.to_int sec.Macho.sec_reserved1 in
  let reserved2_val = Unsigned.UInt32.to_int sec.Macho.sec_reserved2 in
  match sec.Macho.sec_type with
  | `S_SYMBOL_STUBS | `S_LAZY_SYMBOL_POINTERS | `S_NON_LAZY_SYMBOL_POINTERS ->
      Printf.printf " reserved1 %d (index into indirect symbol table)\n"
        reserved1_val;
      if reserved2_val > 0 then
        Printf.printf " reserved2 %d (size of stubs)\n" reserved2_val
      else Printf.printf " reserved2 %d\n" reserved2_val
  | _ ->
      Printf.printf " reserved1 %d\n" reserved1_val;
      Printf.printf " reserved2 %d\n" reserved2_val

let calc_segment_cmdsize is_64bit nsects =
  let base_size = if is_64bit then 72 else 56 in
  let section_size = if is_64bit then 80 else 68 in
  base_size + (nsects * section_size)

let print_segment seg is_64bit =
  let nsects = Array.length seg.Macho.seg_sections in
  let cmdsize = calc_segment_cmdsize is_64bit nsects in
  Printf.printf "      cmd %s\n"
    (if is_64bit then "LC_SEGMENT_64" else "LC_SEGMENT");
  Printf.printf "  cmdsize %d\n" cmdsize;
  Printf.printf "  segname %s\n" seg.Macho.seg_segname;
  if is_64bit then (
    Printf.printf "   vmaddr 0x%016Lx\n"
      (Unsigned.UInt64.to_int64 seg.Macho.seg_vmaddr);
    Printf.printf "   vmsize 0x%016Lx\n"
      (Unsigned.UInt64.to_int64 seg.Macho.seg_vmsize);
    Printf.printf "  fileoff %Ld\n"
      (Unsigned.UInt64.to_int64 seg.Macho.seg_fileoff);
    Printf.printf " filesize %Ld\n"
      (Unsigned.UInt64.to_int64 seg.Macho.seg_filesize))
  else (
    Printf.printf "   vmaddr 0x%08Lx\n"
      (Unsigned.UInt64.to_int64 seg.Macho.seg_vmaddr);
    Printf.printf "   vmsize 0x%08Lx\n"
      (Unsigned.UInt64.to_int64 seg.Macho.seg_vmsize);
    Printf.printf "  fileoff %Ld\n"
      (Unsigned.UInt64.to_int64 seg.Macho.seg_fileoff);
    Printf.printf " filesize %Ld\n"
      (Unsigned.UInt64.to_int64 seg.Macho.seg_filesize));
  Printf.printf "  maxprot 0x%08x\n"
    (Macho.vm_prot_to_int seg.Macho.seg_maxprot);
  Printf.printf " initprot 0x%08x\n"
    (Macho.vm_prot_to_int seg.Macho.seg_initprot);
  Printf.printf "   nsects %d\n" nsects;
  Printf.printf "    flags 0x%x\n" (Macho.seg_flags_to_int seg.Macho.seg_flags);
  Array.iter print_section seg.Macho.seg_sections

let calc_dylib_cmdsize name =
  let base = 24 in
  let name_len = String.length name + 1 in
  let total = base + name_len in
  (total + 7) / 8 * 8

let format_timestamp timestamp =
  let day_names = [| "Sun"; "Mon"; "Tue"; "Wed"; "Thu"; "Fri"; "Sat" |] in
  let month_names =
    [|
      "Jan";
      "Feb";
      "Mar";
      "Apr";
      "May";
      "Jun";
      "Jul";
      "Aug";
      "Sep";
      "Oct";
      "Nov";
      "Dec";
    |]
  in
  let tm = Unix.localtime (float_of_int timestamp) in
  Printf.sprintf "%s %s %2d %02d:%02d:%02d %d"
    day_names.(tm.Unix.tm_wday)
    month_names.(tm.Unix.tm_mon)
    tm.Unix.tm_mday tm.Unix.tm_hour tm.Unix.tm_min tm.Unix.tm_sec
    (1900 + tm.Unix.tm_year)

let print_dylib dylib cmd_name =
  let name = dylib.Macho.dylib_name in
  let display_name =
    (* Check if path starts with / and has no more / after position 0 *)
    if
      String.length name > 1
      && name.[0] = '/'
      && not (String.contains (String.sub name 1 (String.length name - 1)) '/')
    then "/usr/lib" ^ name
    else name
  in
  let cmdsize_display = calc_dylib_cmdsize display_name in
  let timestamp = Unsigned.UInt32.to_int dylib.Macho.dylib_timestamp in
  Printf.printf "          cmd %s\n" cmd_name;
  Printf.printf "      cmdsize %d\n" cmdsize_display;
  Printf.printf "         name %s (offset 24)\n" display_name;
  Printf.printf "   time stamp %d %s\n" timestamp (format_timestamp timestamp);
  Printf.printf "      current version %s\n"
    (format_version dylib.Macho.dylib_current_version);
  Printf.printf "compatibility version %s\n"
    (format_version dylib.Macho.dylib_compatibility_version)

let calc_lc_str_cmdsize name =
  let base = 12 in
  let name_len = String.length name + 1 in
  let total = base + name_len in
  (total + 7) / 8 * 8

let print_dylinker name cmd_name =
  let display_name =
    if name = "/dyld" then "/usr/lib/dyld"
    else if
      String.length name > 1
      && name.[0] = '/'
      && not (String.contains (String.sub name 1 (String.length name - 1)) '/')
    then "/usr/lib" ^ name
    else name
  in
  let cmdsize = calc_lc_str_cmdsize display_name in
  print_cmd_header ~width:13 cmd_name cmdsize;
  Printf.printf "%13s %s\n" "name" (display_name ^ " (offset 12)")

let print_uuid uuid =
  print_cmd_header ~width:8 "LC_UUID" 24;
  let len = String.length uuid in
  let parts = ref [] in
  for i = 0 to min 15 (len - 1) do
    parts := Printf.sprintf "%02X" (Char.code uuid.[i]) :: !parts;
    if i = 3 || i = 5 || i = 7 || i = 9 then parts := "-" :: !parts
  done;
  Printf.printf "%8s %s\n" "uuid" (String.concat "" (List.rev !parts))

let print_rpath path =
  let cmdsize = calc_lc_str_cmdsize path in
  print_cmd_header "LC_RPATH" cmdsize;
  Printf.printf "%7s %s\n" "path" (path ^ " (offset 12)")

let print_linkedit_data cmd_name offset size =
  print_cmd_header ~width:9 cmd_name 16;
  Printf.printf "%9s %d\n" "dataoff" (Unsigned.UInt32.to_int offset);
  Printf.printf "%9s %d\n" "datasize" (Unsigned.UInt32.to_int size)

let print_sub_command cmd_name label name =
  let cmdsize = calc_lc_str_cmdsize name in
  print_cmd_header cmd_name cmdsize;
  Printf.printf "%14s %s\n" label (name ^ " (offset 12)")

let print_prebind_cksum cksum =
  print_cmd_header "LC_PREBIND_CKSUM" 16;
  Printf.printf "%10s 0x%08x\n" "cksum" (Unsigned.UInt32.to_int cksum)

let print_symtab symtab =
  let st = Lazy.force symtab in
  print_cmd_header "LC_SYMTAB" 24;
  Format.printf "%8s %d@." "symoff" (Unsigned.UInt32.to_int st.Macho.symoff);
  Format.printf "%8s %d@." "nsyms" (Unsigned.UInt32.to_int st.Macho.nsyms);
  Format.printf "%8s %d@." "stroff" (Unsigned.UInt32.to_int st.Macho.stroff);
  Format.printf "%8s %d@." "strsize" (Unsigned.UInt32.to_int st.Macho.strsize)

let print_dysymtab dysymtab =
  let dst = Lazy.force dysymtab in
  print_cmd_header ~width:15 "LC_DYSYMTAB" 80;
  Format.printf "%15s %d@." "ilocalsym"
    (Unsigned.UInt32.to_int dst.Macho.ilocalsym);
  Format.printf "%15s %d@." "nlocalsym"
    (Unsigned.UInt32.to_int dst.Macho.nlocalsym);
  Format.printf "%15s %d@." "iextdefsym"
    (Unsigned.UInt32.to_int dst.Macho.iextdefsym);
  Format.printf "%15s %d@." "nextdefsym"
    (Unsigned.UInt32.to_int dst.Macho.nextdefsym);
  Format.printf "%15s %d@." "iundefsym"
    (Unsigned.UInt32.to_int dst.Macho.iundefsym);
  Format.printf "%15s %d@." "nundefsym"
    (Unsigned.UInt32.to_int dst.Macho.nundefsym);
  Format.printf "%15s %d@." "tocoff" (Unsigned.UInt32.to_int dst.Macho.tocoff);
  Format.printf "%15s %d@." "ntoc" (Unsigned.UInt32.to_int dst.Macho.ntoc);
  Format.printf "%15s %d@." "modtaboff"
    (Unsigned.UInt32.to_int dst.Macho.modtaboff);
  Format.printf "%15s %d@." "nmodtab" (Unsigned.UInt32.to_int dst.Macho.nmodtab);
  Format.printf "%15s %d@." "extrefsymoff"
    (Unsigned.UInt32.to_int dst.Macho.extrefsymoff);
  Format.printf "%15s %d@." "nextrefsyms"
    (Unsigned.UInt32.to_int dst.Macho.nextrefsyms);
  Format.printf "%15s %d@." "indirectsymoff"
    (Unsigned.UInt32.to_int dst.Macho.indirectsymoff);
  Format.printf "%15s %d@." "nindirectsyms"
    (Unsigned.UInt32.to_int dst.Macho.nindirectsyms);
  Format.printf "%15s %d@." "extreloff"
    (Unsigned.UInt32.to_int dst.Macho.extreloff);
  Format.printf "%15s %d@." "nextrel" (Unsigned.UInt32.to_int dst.Macho.nextrel);
  Format.printf "%15s %d@." "locreloff"
    (Unsigned.UInt32.to_int dst.Macho.locreloff);
  Format.printf "%15s %d@." "nlocrel" (Unsigned.UInt32.to_int dst.Macho.nlocrel)

let print_main entryoff stacksize =
  print_cmd_header ~width:10 "LC_MAIN" 24;
  Printf.printf "%10s %Ld\n" "entryoff" (Unsigned.UInt64.to_int64 entryoff);
  Printf.printf "%10s %Ld\n" "stacksize" (Unsigned.UInt64.to_int64 stacksize)

let format_source_version v =
  let a = Unsigned.UInt64.to_int64 v in
  let major = Int64.shift_right a 40 in
  let minor = Int64.logand (Int64.shift_right a 30) 0x3ffL in
  let patch = Int64.logand (Int64.shift_right a 20) 0x3ffL in
  if patch = 0L then Printf.sprintf "%Ld.%Ld" major minor
  else Printf.sprintf "%Ld.%Ld.%Ld" major minor patch

let print_source_version version =
  print_cmd_header ~width:9 "LC_SOURCE_VERSION" 16;
  Printf.printf "%9s %s\n" "version" (format_source_version version)

let format_build_version v =
  let x = Unsigned.UInt32.to_int v in
  let major = x lsr 16 in
  let minor = (x lsr 8) land 0xff in
  let patch = x land 0xff in
  if patch = 0 then Printf.sprintf "%d.%d" major minor
  else Printf.sprintf "%d.%d.%d" major minor patch

let print_build_version build_info =
  let info = Lazy.force build_info in
  let cmdsize = 24 + (Array.length info.Macho.tools * 8) in
  print_cmd_header ~width:9 "LC_BUILD_VERSION" cmdsize;
  Format.printf "%9s %d@." "platform"
    (Unsigned.UInt32.to_int info.Macho.platform);
  Format.printf "%9s %s@." "minos" (format_build_version info.Macho.minos);
  Format.printf "%9s %s@." "sdk" (format_build_version info.Macho.sdk);
  Format.printf "%9s %d@." "ntools" (Array.length info.Macho.tools);
  Array.iter
    (fun t ->
      Format.printf "%9s %d@." "tool" (Unsigned.UInt32.to_int t.Macho.tool);
      Format.printf "%9s %s@." "version" (format_build_version t.Macho.version))
    info.Macho.tools

let print_unhandled cmd_num = print_cmd_header (Printf.sprintf "0x%x" cmd_num) 0

let print_load_command idx cmd =
  Printf.printf "Load command %d\n" idx;
  let cmd_name = Macho.command_name cmd in
  match cmd with
  | Macho.LC_SEGMENT_32 lazy_seg ->
      let seg = Lazy.force lazy_seg in
      print_segment seg false
  | Macho.LC_SEGMENT_64 lazy_seg ->
      let seg = Lazy.force lazy_seg in
      print_segment seg true
  | Macho.LC_LOAD_DYLIB lazy_dylib ->
      let dylib = Lazy.force lazy_dylib in
      print_dylib dylib cmd_name
  | Macho.LC_ID_DYLIB lazy_dylib ->
      let dylib = Lazy.force lazy_dylib in
      print_dylib dylib cmd_name
  | Macho.LC_LOAD_WEAK_DYLIB lazy_dylib ->
      let dylib = Lazy.force lazy_dylib in
      print_dylib dylib cmd_name
  | Macho.LC_LOAD_DYLINKER name -> print_dylinker name cmd_name
  | Macho.LC_ID_DYLINKER name -> print_dylinker name cmd_name
  | Macho.LC_UUID uuid -> print_uuid uuid
  | Macho.LC_RPATH path -> print_rpath path
  | Macho.LC_CODE_SIGNATURE (offset, size) ->
      print_linkedit_data cmd_name offset size
  | Macho.LC_SEGMENT_SPLIT_INFO (offset, size) ->
      print_linkedit_data cmd_name offset size
  | Macho.LC_ROUTINES_32 (addr, module_idx) ->
      print_cmd_header cmd_name 68;
      Printf.printf "%15s 0x%08x\n" "init_address" (Unsigned.UInt32.to_int addr);
      Printf.printf "%13s %d\n" "init_module"
        (Unsigned.UInt32.to_int module_idx)
  | Macho.LC_ROUTINES_64 (addr, module_idx) ->
      print_cmd_header cmd_name 80;
      Printf.printf "%15s 0x%016Lx\n" "init_address"
        (Unsigned.UInt64.to_int64 addr);
      Printf.printf "%13s %Ld\n" "init_module"
        (Unsigned.UInt64.to_int64 module_idx)
  | Macho.LC_SUB_FRAMEWORK name -> print_sub_command cmd_name "  umbrella" name
  | Macho.LC_SUB_UMBRELLA name ->
      print_sub_command cmd_name "  sub_umbrella" name
  | Macho.LC_SUB_CLIENT name -> print_sub_command cmd_name "    client" name
  | Macho.LC_SUB_LIBRARY name -> print_sub_command cmd_name "  sub_library" name
  | Macho.LC_PREBIND_CKSUM cksum -> print_prebind_cksum cksum
  | Macho.LC_SYMTAB symtab -> print_symtab symtab
  | Macho.LC_DYSYMTAB dysymtab -> print_dysymtab dysymtab
  | Macho.LC_THREAD _ -> print_cmd_header cmd_name 0
  | Macho.LC_UNIXTHREAD _ -> print_cmd_header cmd_name 0
  | Macho.LC_PREBOUND_DYLIB _ -> print_cmd_header cmd_name 0
  | Macho.LC_TWOLEVEL_HINTS _ -> print_cmd_header cmd_name 0
  | Macho.LC_MAIN (entryoff, stacksize) -> print_main entryoff stacksize
  | Macho.LC_SOURCE_VERSION version -> print_source_version version
  | Macho.LC_BUILD_VERSION build_info -> print_build_version build_info
  | Macho.LC_FUNCTION_STARTS (offset, size) ->
      print_linkedit_data cmd_name offset size
  | Macho.LC_DATA_IN_CODE (offset, size) ->
      print_linkedit_data cmd_name offset size
  | Macho.LC_DYLD_EXPORTS_TRIE (offset, size) ->
      print_linkedit_data cmd_name offset size
  | Macho.LC_DYLD_CHAINED_FIXUPS (offset, size) ->
      print_linkedit_data cmd_name offset size
  | Macho.LC_UNHANDLED (cmd_num, _) -> print_unhandled cmd_num

let print_load_commands filename buffer =
  let _header, commands = Macho.read buffer in
  Printf.printf "%s:\n" filename;
  List.iteri print_load_command commands

let octool fat_headers load_commands file =
  let buffer = Object.Buffer.parse file in
  if fat_headers then (
    print_fat_header file buffer;
    `Ok ())
  else if load_commands then (
    if Macho.is_fat buffer then
      let fat_header = Macho.read_fat buffer in
      let native_arch = get_native_arch () in
      let arch_to_use =
        match
          Array.find_opt
            (fun arch ->
              let name = Macho.arch_name arch in
              name = native_arch || (native_arch = "arm64" && name = "arm64e"))
            fat_header.fat_archs
        with
        | Some arch -> arch
        | None -> fat_header.fat_archs.(0)
      in
      let arch_buffer = Macho.extract_arch buffer arch_to_use in
      print_load_commands file arch_buffer
    else print_load_commands file buffer;
    `Ok ())
  else `Ok ()

let fat_headers =
  let doc = "Display the fat headers" in
  Arg.(value & flag & info [ "f" ] ~doc)

let load_commands =
  let doc = "Display the load commands" in
  Arg.(value & flag & info [ "l" ] ~doc)

let file =
  let doc = "Mach-O file to analyze" in
  Arg.(required & pos 0 (some string) None & info [] ~docv:"FILE" ~doc)

let octool_t = Term.(ret (const octool $ fat_headers $ load_commands $ file))

let info =
  let doc = "display Mach-O object files" in
  let man =
    [
      `S Manpage.s_description;
      `P "Display information about Mach-O object files.";
    ]
  in
  Cmd.info "octool" ~version:"1.0" ~doc ~man

let () = exit (Cmd.eval (Cmd.v info octool_t))
