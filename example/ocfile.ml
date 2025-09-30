(* Implement file command to correctly identify different object files. *)

open Object
open Cmdliner

let identify_file filename buffer =
  if Macho.is_fat buffer then (
    let fat_header = Macho.read_fat buffer in
    let nfat_arch = Array.length fat_header.fat_archs in
    Printf.printf "%s: Mach-O universal binary with %d architectures: ["
      filename nfat_arch;
    Array.iteri
      (fun i arch ->
        let arch_str = Macho.arch_name arch in
        let file_desc = "Mach-O 64-bit executable" in
        if i > 0 then Printf.printf " ";
        Printf.printf "%s:%s %s" arch_str file_desc arch_str)
      fat_header.fat_archs;
    Printf.printf "]\n";
    Array.iter
      (fun arch ->
        let arch_str = Macho.arch_name arch in
        Printf.printf "%s (for architecture %s):\tMach-O 64-bit executable %s\n"
          filename arch_str arch_str)
      fat_header.fat_archs)
  else Printf.printf "%s: Mach-O single architecture file\n" filename

let ocfile file =
  let buffer = Object.Buffer.parse file in
  identify_file file buffer;
  `Ok ()

let file =
  let doc = "Object file to identify" in
  Arg.(required & pos 0 (some string) None & info [] ~docv:"FILE" ~doc)

let ocfile_t = Term.(ret (const ocfile $ file))

let info =
  let doc = "identify object file types" in
  let man =
    [
      `S Manpage.s_description;
      `P "Identify and display information about object file types.";
    ]
  in
  Cmd.info "ocfile" ~version:"1.0" ~doc ~man

let () = exit (Cmd.eval (Cmd.v info ocfile_t))
