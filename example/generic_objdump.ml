(** Generic object file dumper using the unified Object.Object_format interface
*)

open Cmdliner

let print_header (obj : Object.Object_format.t) =
  let header = obj.header in
  let format_str =
    match header.format with
    | Object.Object_format.ELF -> "ELF"
    | Object.Object_format.MACHO -> "Mach-O"
  in
  let arch_str =
    match header.architecture with
    | `X86 -> "x86"
    | `X86_64 -> "x86_64"
    | `ARM -> "arm"
    | `ARM64 -> "arm64"
    | `POWERPC -> "powerpc"
    | `POWERPC64 -> "powerpc64"
    | `Unknown n -> Printf.sprintf "unknown(%d)" n
  in
  Printf.printf "Format: %s\n" format_str;
  Printf.printf "Architecture: %s\n" arch_str;
  Printf.printf "64-bit: %b\n" header.is_64bit;
  Printf.printf "Executable: %b\n" header.is_executable;
  (match header.entry_point with
  | Some entry ->
      Printf.printf "Entry Point: 0x%Lx\n" (Unsigned.UInt64.to_int64 entry)
  | None -> Printf.printf "Entry Point: N/A\n");
  Printf.printf "\n"

let print_segments (obj : Object.Object_format.t) =
  let segments = Object.Object_format.segments obj in
  Printf.printf "Segments (%d):\n" (Array.length segments);
  Printf.printf "%-16s %-16s %-16s %-12s %-12s %s\n" "Name" "VirtAddr"
    "VirtSize" "FileOffset" "FileSize" "Sections";
  Array.iteri
    (fun _i seg ->
      Printf.printf "%-16s %016Lx %016Lx %012Lx %012Lx %d\n"
        seg.Object.Object_format.name
        (Unsigned.UInt64.to_int64 seg.virtual_address)
        (Unsigned.UInt64.to_int64 seg.virtual_size)
        (Unsigned.UInt64.to_int64 seg.file_offset)
        (Unsigned.UInt64.to_int64 seg.file_size)
        (Array.length seg.sections))
    segments;
  Printf.printf "\n"

let print_sections (obj : Object.Object_format.t) =
  let sections = Object.Object_format.sections obj in
  Printf.printf "Sections (%d):\n" (Array.length sections);
  Printf.printf "%-3s %-20s %-16s %-16s %-12s %s\n" "Idx" "Name" "Size"
    "Address" "Offset" "Type";
  Array.iteri
    (fun i sec ->
      let offset_str =
        match sec.Object.Object_format.offset with
        | Some off -> Printf.sprintf "%012Lx" (Unsigned.UInt64.to_int64 off)
        | None -> "N/A"
      in
      Printf.printf "%3d %-20s %016Lx %016Lx %-12s %s\n" i
        sec.Object.Object_format.name
        (Unsigned.UInt64.to_int64 sec.size)
        (Unsigned.UInt64.to_int64 sec.address)
        offset_str sec.section_type)
    sections;
  Printf.printf "\n"

let dump_file filename =
  try
    let buffer = Object.Buffer.parse filename in
    let obj = Object.Object_format.read buffer in

    Printf.printf "=== %s ===\n\n" filename;
    print_header obj;
    print_segments obj;
    print_sections obj;

    (* Example: Find and read a specific section *)
    match Object.Object_format.find_section obj "__cstring" with
    | Some section ->
        Printf.printf "Found __cstring section (size: %Ld bytes)\n"
          (Unsigned.UInt64.to_int64 section.Object.Object_format.size);
        let content =
          Object.Object_format.section_contents buffer obj section
        in
        Printf.printf "First few bytes: ";
        for i = 0 to min 15 (Bigarray.Array1.dim content - 1) do
          let byte = Bigarray.Array1.get content i in
          Printf.printf "%02x " byte
        done;
        Printf.printf "\n\n"
    | None -> ()
  with exn ->
    Printf.eprintf "Error processing %s: %s\n" filename (Printexc.to_string exn)

let generic_objdump files =
  List.iter (fun file -> ignore (dump_file file)) files;
  `Ok ()

let files =
  let doc = "Object files to analyze" in
  Arg.(non_empty & pos_all string [] & info [] ~docv:"FILES" ~doc)

let generic_objdump_t = Term.(ret (const generic_objdump $ files))

let info =
  let doc = "generic object file dumper" in
  let man =
    [
      `S Manpage.s_description;
      `P "Display information about object files using a unified interface.";
    ]
  in
  Cmd.info "generic_objdump" ~version:"1.0" ~doc ~man

let () = exit (Cmd.eval (Cmd.v info generic_objdump_t))
