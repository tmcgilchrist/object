(** OCaml implementation of objdump for MachO binaries. should be equivalent to

    objdump --section-headers <binaries> *)
let cpu_type_to_string = function
  | `X86 -> "x86_32"
  | `X86_64 -> "x86_64"
  | `ARM -> "arm32"
  | `ARM64 -> "arm64"
  | `POWERPC -> "ppc32"
  | `POWERPC64 -> "ppc64"
  | _unknown -> "unknown"

let print_summary file (header : Object.Macho.header) =
  Printf.printf "\n%s:\tfile format mach-o %s\n\n" file
    (cpu_type_to_string header.cpu_type)

let print_section_headers file =
  let open Printf in
  let buffer = Object.Buffer.parse file in
  let header, commands = Object.Macho.read buffer in
  print_summary file header;
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

let run section_headers files () =
  match section_headers with
  | true -> List.iter print_section_headers files
  | false ->
      Printf.printf
        "Section headers flag required please call with `--section-headers`.\n";
      exit 2

open Cmdliner

let section_headers =
  (* Documentation string *)
  let doc = "Display summaries of the headers for each section.." in
  (* Other *)
  let info = Arg.(info [ "section-headers" ] ~doc) in
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
