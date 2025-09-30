(* OCaml implementation of otool for MachO binaries. *)

open Object
open Cmdliner

let cpu_type_to_int = function
  | `X86 -> 7
  | `X86_64 -> 0x01000007
  | `ARM -> 12
  | `ARM64 -> 0x0100000c
  | `ARM64_32 -> 0x0200000c
  | `POWERPC -> 18
  | `POWERPC64 -> 0x01000012
  | `Unknown n -> n

let cpu_subtype_to_int ty subtype =
  match (ty, subtype) with
  | `X86_64, `X86_64_ALL -> 3
  | `ARM64, `ARM_ALL -> 0
  | `ARM64, `ARM_V8 -> 1
  | `ARM, `ARM_V7 -> 9
  | `Unknown _, `Unknown n -> n
  | _, _ -> 0

let print_fat_header filename buffer =
  if not (Macho.is_fat buffer) then
    Printf.printf "%s is not a fat file\n" filename
  else
    let fat_header = Macho.read_fat buffer in
    let nfat_arch = Array.length fat_header.fat_archs in
    Printf.printf "Fat headers\n";
    Printf.printf "fat_magic 0x%x\n"
      (match fat_header.fat_magic with
      | Macho.FAT_MAGIC -> 0xcafebabe
      | Macho.FAT_CIGAM -> 0xbebafeca
      | Macho.FAT_MAGIC_64 -> 0xcafebabf
      | Macho.FAT_CIGAM_64 -> 0xbfbafeca);
    Printf.printf "nfat_arch %d\n" nfat_arch;
    Array.iteri
      (fun i arch ->
        Printf.printf "architecture %d\n" i;
        match arch with
        | `Fat_arch fa ->
            let cputype_int = cpu_type_to_int fa.Macho.fa_cputype in
            let cpusubtype_val =
              match fa.Macho.fa_cpusubtype with
              | `Unknown n -> n
              | subtype -> cpu_subtype_to_int fa.Macho.fa_cputype subtype
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
            let cputype_int = cpu_type_to_int fa64.Macho.fa64_cputype in
            let cpusubtype_val =
              match fa64.Macho.fa64_cpusubtype with
              | `Unknown n -> n
              | subtype -> cpu_subtype_to_int fa64.Macho.fa64_cputype subtype
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

let octool fat_headers file =
  let buffer = Object.Buffer.parse file in
  if fat_headers then (
    print_fat_header file buffer;
    `Ok ())
  else `Ok ()

let fat_headers =
  let doc = "Display the fat headers" in
  Arg.(value & flag & info [ "f" ] ~doc)

let file =
  let doc = "Mach-O file to analyze" in
  Arg.(required & pos 0 (some string) None & info [] ~docv:"FILE" ~doc)

let octool_t = Term.(ret (const octool $ fat_headers $ file))

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
