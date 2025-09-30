(* OCaml implementation of lipo for manipulating FAT/Universal binaries. *)

open Object
open Cmdliner

let print_info filename buffer =
  if not (Macho.is_fat buffer) then
    Printf.printf "Non-fat file: %s is architecture: %s\n" filename "unknown"
  else
    let fat_header = Macho.read_fat buffer in
    Printf.printf "Architectures in the fat file: %s are: " filename;
    let archs =
      Array.map Macho.arch_name fat_header.fat_archs |> Array.to_list
    in
    Printf.printf "%s \n" (String.concat " " archs)

let print_detailed_info filename buffer =
  if not (Macho.is_fat buffer) then
    Printf.printf "input file %s is not a fat file\n" filename
  else
    let fat_header = Macho.read_fat buffer in
    let nfat_arch = Array.length fat_header.fat_archs in
    Printf.printf "Fat header in: %s\n" filename;
    Printf.printf "fat_magic 0x%x\n"
      (match fat_header.fat_magic with
      | Macho.FAT_MAGIC -> 0xcafebabe
      | Macho.FAT_CIGAM -> 0xbebafeca
      | Macho.FAT_MAGIC_64 -> 0xcafebabf
      | Macho.FAT_CIGAM_64 -> 0xbfbafeca);
    Printf.printf "nfat_arch %d\n" nfat_arch;
    Array.iter
      (fun arch ->
        let arch_str = Macho.arch_name arch in
        match arch with
        | `Fat_arch fa ->
            let cpusubtype_val =
              match fa.Macho.fa_cpusubtype with `Unknown n -> n | _ -> 0
            in
            let capabilities = (cpusubtype_val lsr 24) land 0xff in
            Printf.printf "architecture %s\n" arch_str;
            Printf.printf "    cputype CPU_TYPE_%s\n"
              (String.uppercase_ascii arch_str);
            Printf.printf "    cpusubtype CPU_SUBTYPE_%s_ALL\n"
              (String.uppercase_ascii arch_str);
            Printf.printf "    capabilities 0x%x\n" capabilities;
            Printf.printf "    offset %d\n"
              (Unsigned.UInt32.to_int fa.Macho.fa_offset);
            Printf.printf "    size %d\n"
              (Unsigned.UInt32.to_int fa.Macho.fa_size);
            Printf.printf "    align 2^%d (%d)\n"
              (Unsigned.UInt32.to_int fa.Macho.fa_align)
              (1 lsl Unsigned.UInt32.to_int fa.Macho.fa_align)
        | `Fat_arch_64 fa64 ->
            Printf.printf "architecture %s\n" arch_str;
            Printf.printf "    cputype CPU_TYPE_%s\n"
              (String.uppercase_ascii arch_str);
            Printf.printf "    cpusubtype CPU_SUBTYPE_%s\n"
              (if arch_str = "arm64e" then "ARM64E"
               else String.uppercase_ascii arch_str ^ "_ALL");
            Printf.printf "    capabilities PTR_AUTH_VERSION USERSPACE 0\n";
            Printf.printf "    offset %Ld\n"
              (Unsigned.UInt64.to_int64 fa64.Macho.fa64_offset);
            Printf.printf "    size %Ld\n"
              (Unsigned.UInt64.to_int64 fa64.Macho.fa64_size);
            Printf.printf "    align 2^%d (%d)\n"
              (Unsigned.UInt32.to_int fa64.Macho.fa64_align)
              (1 lsl Unsigned.UInt32.to_int fa64.Macho.fa64_align))
      fat_header.fat_archs

let print_archs filename buffer =
  if not (Macho.is_fat buffer) then
    Printf.printf "Non-fat file: %s is architecture: %s\n" filename "unknown"
  else
    let fat_header = Macho.read_fat buffer in
    let archs = Array.map Macho.arch_name fat_header.fat_archs in
    Printf.printf "%s\n" (String.concat " " (Array.to_list archs))

let verify_arch filename buffer arch_names =
  if not (Macho.is_fat buffer) then (
    Printf.printf "Non-fat file: %s is not a fat file\n" filename;
    `Error (false, "Not a FAT file"))
  else
    let fat_header = Macho.read_fat buffer in
    let available_archs =
      Array.map Macho.arch_name fat_header.fat_archs |> Array.to_list
    in
    let all_found =
      List.for_all
        (fun arch_name -> List.mem arch_name available_archs)
        arch_names
    in
    if not all_found then (
      List.iter
        (fun arch_name ->
          if not (List.mem arch_name available_archs) then (
            Printf.printf "fat file: %s does not contain an architecture for "
              filename;
            Printf.printf "specified architecture type: %s\n" arch_name))
        arch_names;
      `Error (false, "Architecture not found"))
    else `Ok ()

let oclipo info detailed_info archs verify_archs file =
  let buffer = Object.Buffer.parse file in
  if info then (
    print_info file buffer;
    `Ok ())
  else if detailed_info then (
    print_detailed_info file buffer;
    `Ok ())
  else if archs then (
    print_archs file buffer;
    `Ok ())
  else if verify_archs <> [] then verify_arch file buffer verify_archs
  else `Error (true, "No command specified")

let info_flag =
  let doc = "Display basic architecture info" in
  Arg.(value & flag & info [ "info" ] ~doc)

let detailed_info_flag =
  let doc = "Display detailed fat header info" in
  Arg.(value & flag & info [ "detailed_info" ] ~doc)

let archs_flag =
  let doc = "Display architecture names" in
  Arg.(value & flag & info [ "archs" ] ~doc)

let verify_arch_arg =
  let doc = "Verify specified architectures are present" in
  Arg.(value & opt_all string [] & info [ "verify_arch" ] ~docv:"ARCH" ~doc)

let file =
  let doc = "FAT binary file to analyze" in
  Arg.(required & pos 0 (some string) None & info [] ~docv:"FILE" ~doc)

let oclipo_t =
  Term.(
    ret
      (const oclipo $ info_flag $ detailed_info_flag $ archs_flag
     $ verify_arch_arg $ file))

let info =
  let doc = "manipulate FAT/Universal binaries" in
  let man =
    [
      `S Manpage.s_description;
      `P "Display information about FAT/Universal binaries.";
    ]
  in
  Cmd.info "oclipo" ~version:"1.0" ~doc ~man

let () = exit (Cmd.eval (Cmd.v info oclipo_t))
