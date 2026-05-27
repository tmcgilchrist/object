(** Reader acceptance test against a real COFF object file produced by the
    toolchain (built at test time when a Windows-targeting cross-compiler is
    available). *)

let test_format_detection binary =
  let buf = Object.Buffer.parse binary in
  Alcotest.(check bool) "is_coff" true (Object.Pe.is_coff buf);
  Alcotest.(check bool) "not is_pe" false (Object.Pe.is_pe buf)

let test_headers binary =
  let buf = Object.Buffer.parse binary in
  let pe = Object.Pe.read buf in
  Alcotest.(check bool)
    "no optional header" true
    (pe.Object.Pe.optional_header = None);
  Alcotest.(check string)
    "machine" "amd64"
    (Object.Pe.machine_type_to_string pe.Object.Pe.coff_header.Object.Pe.machine);
  Alcotest.(check bool)
    "has sections" true
    (Array.length pe.Object.Pe.section_headers > 0)

let test_has_text_section binary =
  let buf = Object.Buffer.parse binary in
  let pe = Object.Pe.read buf in
  let has_text =
    Array.exists
      (fun (sh : Object.Pe.section_header) -> sh.name = ".text")
      pe.Object.Pe.section_headers
  in
  Alcotest.(check bool) "has .text" true has_text

let test_has_symbols binary =
  let buf = Object.Buffer.parse binary in
  let pe = Object.Pe.read buf in
  let syms = Object.Pe.read_symbols buf pe in
  Alcotest.(check bool) "has symbols" true (Array.length syms > 0)

let binary_path =
  let doc = "Path to the COFF object file produced by the toolchain." in
  Cmdliner.Arg.(
    required & opt (some file) None & info [ "binary"; "b" ] ~doc ~docv:"BINARY")

let () =
  Alcotest.run_with_args "PE/COFF real fixture" binary_path
    [
      ( "coff object",
        [
          ("format detection", `Quick, test_format_detection);
          ("headers", `Quick, test_headers);
          ("has .text section", `Quick, test_has_text_section);
          ("has symbols", `Quick, test_has_symbols);
        ] );
    ]
