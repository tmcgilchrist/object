(** OCaml implementation of objdump for object files. Supports ELF, Mach-O, and
    PE formats. Should be equivalent to objdump --section-headers <binaries> *)

let cpu_type_to_string = function
  | `X86 -> "x86_32"
  | `X86_64 -> "x86_64"
  | `ARM -> "arm32"
  | `ARM64 -> "arm64"
  | `ARM64_32 -> "arm64_32"
  | `POWERPC -> "ppc32"
  | `POWERPC64 -> "ppc64"
  | `Unknown n -> Printf.sprintf "unknown(%d)" n

let print_macho_summary file (header : Object.Macho.header) =
  Printf.printf "\n%s:\tfile format mach-o %s\n\n" file
    (cpu_type_to_string header.cpu_type)

let print_pe_summary file (pe_obj : Object.Pe.pe_object) =
  let format_str =
    if Object.Pe.is_64bit pe_obj then "coff-x86-64" else "coff-i386"
  in
  Printf.printf "\n%s:\tfile format %s\n\n" file format_str

let print_macho_sections file =
  let open Printf in
  let buffer = Object.Buffer.parse file in
  let header, commands = Object.Macho.read buffer in
  print_macho_summary file header;
  printf "Sections:\n";
  printf "%3s %-13s %-8s %-16s %s\n" "Idx" "Name" "Size" "VMA" "Type";

  let section_index = ref 0 in
  let print_section (_segment : Object.Macho.segment)
      (section : Object.Macho.section) =
    let section_type =
      if section.sec_segname = "__TEXT" then "TEXT" else "DATA"
    in
    Printf.printf "%3i %-13s %08Lx %016Lx %s\n" !section_index
      section.sec_sectname
      (Unsigned.UInt64.to_int64 section.sec_size)
      (Unsigned.UInt64.to_int64 section.sec_addr)
      section_type;
    incr section_index
  in

  let process_segment = function
    | Object.Macho.LC_SEGMENT_64 segment | Object.Macho.LC_SEGMENT_32 segment ->
        let (lazy segment) = segment in
        Array.iter (print_section segment) segment.Object.Macho.seg_sections
    | _ -> ()
  in

  List.iter process_segment commands

let print_pe_sections file =
  let open Printf in
  let buffer = Object.Buffer.parse file in
  let pe_obj = Object.Pe.read buffer in
  print_pe_summary file pe_obj;
  printf "Sections:\n";
  printf "%3s %-13s %-8s %-16s %s\n" "Idx" "Name" "Size" "VMA" "Type";

  let sections = Object.Pe.sections pe_obj in
  let image_base =
    match pe_obj.optional_header with
    | Some opt -> opt.image_base
    | None -> Unsigned.UInt64.zero
  in

  Array.iteri
    (fun i section ->
      (* Get section name *)
      let name = section.Object.Pe.name in
      let clean_name =
        if String.length name = 0 then Printf.sprintf ".sec%d" i else name
      in

      (* Use virtual_size if size_of_raw_data is 0 (like for .bss) *)
      let size =
        let raw_size =
          Unsigned.UInt32.to_int64 section.Object.Pe.size_of_raw_data
        in
        if raw_size = 0L then
          Unsigned.UInt32.to_int64 section.Object.Pe.virtual_size
        else raw_size
      in

      (* Calculate proper VMA by adding image_base to virtual_address *)
      let vma =
        Unsigned.UInt64.add image_base
          (Unsigned.UInt64.of_int
             (Unsigned.UInt32.to_int section.Object.Pe.virtual_address))
      in
      let vma_int64 = Unsigned.UInt64.to_int64 vma in

      let section_type =
        Object.Pe.section_characteristics_to_type_string
          section.Object.Pe.characteristics
      in

      printf "%3i %-13s %08Lx %016Lx %s\n" i clean_name size vma_int64
        section_type)
    sections

let print_section_headers file =
  let buffer = Object.Buffer.parse file in
  if Object.Pe.is_pe buffer then print_pe_sections file
  else
    try
      (* Try to read as Mach-O *)
      let _ = Object.Macho.read buffer in
      print_macho_sections file
    with _ -> Printf.printf "Error: Unsupported file format for %s\n" file

let run section_headers files () =
  match section_headers with
  | true -> List.iter print_section_headers files
  | false ->
      Printf.printf
        "Section headers flag required please call with `-h` or \
         `--section-headers`.\n";
      exit 2

open Cmdliner

let section_headers =
  (* Documentation string *)
  let doc = "Display summaries of the headers for each section." in
  (* Add both -h and --section-headers options *)
  let info = Arg.(info [ "h"; "section-headers" ] ~doc) in
  Arg.value (Arg.flag info)

let files =
  let doc = "Object FILEs to read." in
  Arg.(non_empty & pos_all file [] & info [] ~docv:"FILE" ~doc)

let section_headers_t = Term.(const run $ section_headers $ files $ const ())

let cmd =
  let doc = "OCaml object file dumper." in
  let info = Cmd.info "objdump" ~doc in
  Cmd.v info section_headers_t

let () = exit @@ Cmd.eval ~catch:true cmd
