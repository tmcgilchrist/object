(* Unit tests for FAT binary validation *)

open Object

let test_validate_fat_header () =
  Alcotest.(check bool)
    "valid FAT header" true
    (Macho.is_fat (Object.Buffer.parse "/usr/bin/xcrun"))

let test_arch_name () =
  let buffer = Object.Buffer.parse "/usr/bin/xcrun" in
  if Macho.is_fat buffer then
    let fat_header = Macho.read_fat buffer in
    let names = Array.map Macho.arch_name fat_header.fat_archs in
    Alcotest.(check bool)
      "has x86_64 or arm64" true
      (Array.exists
         (fun n -> n = "x86_64" || n = "arm64" || n = "arm64e")
         names)
  else Alcotest.fail "xcrun should be a FAT binary"

let test_find_arch () =
  let buffer = Object.Buffer.parse "/usr/bin/xcrun" in
  if Macho.is_fat buffer then
    let fat_header = Macho.read_fat buffer in
    let available_archs =
      Array.map Macho.arch_name fat_header.fat_archs |> Array.to_list
    in
    List.iter
      (fun arch_name ->
        Alcotest.(check bool)
          (Printf.sprintf "find %s" arch_name)
          true
          (Option.is_some (Macho.find_arch fat_header arch_name)))
      available_archs
  else Alcotest.fail "xcrun should be a FAT binary"

let test_extract_arch_by_name () =
  let buffer = Object.Buffer.parse "/usr/bin/xcrun" in
  if Macho.is_fat buffer then
    let fat_header = Macho.read_fat buffer in
    let available_archs =
      Array.map Macho.arch_name fat_header.fat_archs |> Array.to_list
    in
    List.iter
      (fun arch_name ->
        let extracted = Macho.extract_arch_by_name buffer arch_name in
        Alcotest.(check bool)
          (Printf.sprintf "extract %s" arch_name)
          true (Option.is_some extracted))
      available_archs
  else Alcotest.fail "xcrun should be a FAT binary"

let test_validate_fat () =
  let buffer = Object.Buffer.parse "/usr/bin/xcrun" in
  match Macho.validate_fat buffer with
  | Ok () -> Alcotest.(check bool) "validation passes" true true
  | Error errors ->
      Alcotest.fail
        (Printf.sprintf "validation failed with %d errors" (List.length errors))

let test_list_archs () =
  let buffer = Object.Buffer.parse "/usr/bin/xcrun" in
  let archs = Object_format.list_archs buffer in
  Alcotest.(check bool) "has at least one arch" true (Array.length archs > 0)

let test_read_arch () =
  let buffer = Object.Buffer.parse "/usr/bin/xcrun" in
  let archs = Object_format.list_archs buffer in
  Array.iter
    (fun arch_name ->
      let obj = Object_format.read_arch buffer arch_name in
      Alcotest.(check bool)
        (Printf.sprintf "read %s" arch_name)
        true
        (Object_format.is_64bit obj))
    archs

let test_iter_archs () =
  let buffer = Object.Buffer.parse "/usr/bin/xcrun" in
  let count = ref 0 in
  Object_format.iter_archs buffer (fun _arch_name _obj -> incr count);
  Alcotest.(check bool) "iterated at least one arch" true (!count > 0)

let () =
  if Sys.os_type = "Unix" && Sys.file_exists "/usr/bin/xcrun" then
    let open Alcotest in
    run "FAT Binary Tests"
      [
        ( "validation",
          [
            test_case "validate FAT header" `Quick test_validate_fat_header;
            test_case "arch_name" `Quick test_arch_name;
            test_case "find_arch" `Quick test_find_arch;
            test_case "extract_arch_by_name" `Quick test_extract_arch_by_name;
            test_case "validate_fat" `Quick test_validate_fat;
          ] );
        ( "object_format",
          [
            test_case "list_archs" `Quick test_list_archs;
            test_case "read_arch" `Quick test_read_arch;
            test_case "iter_archs" `Quick test_iter_archs;
          ] );
      ]
  else Printf.printf "Skipping FAT tests (not on macOS or xcrun not found)\n"
