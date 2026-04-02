(** OCaml tool to display DOF (DTrace Object Format) sections from Mach-O

    Similar to readelf -n on Linux ELF systems, this tool displays DTrace probe
    information embedded in Mach-O binaries. *)

[@@@ocaml.warning "-69"]
[@@@ocaml.warning "-32"]
[@@@ocaml.warning "-26"]

open Object
open Cmdliner

module DOF = struct
  open Buffer.Read

  module Magic = struct
    let mag0 = 0x7F
    let mag1 = Char.code 'D'
    let mag2 = Char.code 'O'
    let mag3 = Char.code 'F'
  end

  module Ident = struct
    let model = 4
    let encoding = 5
    let version = 6
    let difvers = 7
  end

  module Model = struct
    let _ilp32 = 1
    let lp64 = 2

    let to_string = function
      | 1 -> "ILP32 (32-bit)"
      | 2 -> "LP64 (64-bit)"
      | n -> Printf.sprintf "Unknown(%d)" n

    let is_64bit m = m = lp64
  end

  module Encoding = struct
    let lsb = 1
    let _msb = 2

    let to_string = function
      | 1 -> "LSB (little-endian)"
      | 2 -> "MSB (big-endian)"
      | n -> Printf.sprintf "Unknown(%d)" n

    let is_little_endian e = e = lsb
  end

  module Sect_type = struct
    type t =
      | None
      | Comments
      | Source
      | Ecbdesc
      | Probedesc
      | Actdesc
      | Difohdr
      | Dif
      | Strtab
      | Vartab
      | Reltab
      | Typtab
      | Urelhdr
      | Krelhdr
      | Optdesc
      | Provider
      | Probes
      | Prargs
      | Proffs
      | Inttab
      | Utsname
      | Xltab
      | Xlmembers
      | Xlimport
      | Xlexport
      | Prexport
      | Prenoffs
      | Unknown of int

    let of_int = function
      | 0 -> None
      | 1 -> Comments
      | 2 -> Source
      | 3 -> Ecbdesc
      | 4 -> Probedesc
      | 5 -> Actdesc
      | 6 -> Difohdr
      | 7 -> Dif
      | 8 -> Strtab
      | 9 -> Vartab
      | 10 -> Reltab
      | 11 -> Typtab
      | 12 -> Urelhdr
      | 13 -> Krelhdr
      | 14 -> Optdesc
      | 15 -> Provider
      | 16 -> Probes
      | 17 -> Prargs
      | 18 -> Proffs
      | 19 -> Inttab
      | 20 -> Utsname
      | 21 -> Xltab
      | 22 -> Xlmembers
      | 23 -> Xlimport
      | 24 -> Xlexport
      | 25 -> Prexport
      | 26 -> Prenoffs
      | n -> Unknown n

    let to_string = function
      | None -> "NONE"
      | Comments -> "COMMENTS"
      | Source -> "SOURCE"
      | Ecbdesc -> "ECBDESC"
      | Probedesc -> "PROBEDESC"
      | Actdesc -> "ACTDESC"
      | Difohdr -> "DIFOHDR"
      | Dif -> "DIF"
      | Strtab -> "STRTAB"
      | Vartab -> "VARTAB"
      | Reltab -> "RELTAB"
      | Typtab -> "TYPTAB"
      | Urelhdr -> "URELHDR"
      | Krelhdr -> "KRELHDR"
      | Optdesc -> "OPTDESC"
      | Provider -> "PROVIDER"
      | Probes -> "PROBES"
      | Prargs -> "PRARGS"
      | Proffs -> "PROFFS"
      | Inttab -> "INTTAB"
      | Utsname -> "UTSNAME"
      | Xltab -> "XLTAB"
      | Xlmembers -> "XLMEMBERS"
      | Xlimport -> "XLIMPORT"
      | Xlexport -> "XLEXPORT"
      | Prexport -> "PREXPORT"
      | Prenoffs -> "PRENOFFS"
      | Unknown n -> Printf.sprintf "UNKNOWN(%d)" n
  end

  module Sect_flags = struct
    let load = 1
  end

  type header = {
    ident : string;
    flags : Unsigned.UInt32.t;
    hdrsize : Unsigned.UInt32.t;
    secsize : Unsigned.UInt32.t;
    secnum : Unsigned.UInt32.t;
    secoff : Unsigned.UInt64.t;
    loadsz : Unsigned.UInt64.t;
    filesz : Unsigned.UInt64.t;
    pad : Unsigned.UInt64.t;
  }

  type section = {
    sect_type : Sect_type.t;
    align : Unsigned.UInt32.t;
    flags : Unsigned.UInt32.t;
    entsize : Unsigned.UInt32.t;
    offset : Unsigned.UInt64.t;
    size : Unsigned.UInt64.t;
  }

  type provider = {
    strtab : Unsigned.UInt32.t;
    probes : Unsigned.UInt32.t;
    prargs : Unsigned.UInt32.t;
    proffs : Unsigned.UInt32.t;
    name : Unsigned.UInt32.t;
    provattr : Unsigned.UInt32.t;
    modattr : Unsigned.UInt32.t;
    funcattr : Unsigned.UInt32.t;
    nameattr : Unsigned.UInt32.t;
    argsattr : Unsigned.UInt32.t;
    prenoffs : Unsigned.UInt32.t;
  }

  type probe = {
    addr : Unsigned.UInt64.t;
    func : Unsigned.UInt32.t;
    name : Unsigned.UInt32.t;
    nargv : Unsigned.UInt32.t;
    xargv : Unsigned.UInt32.t;
    argidx : Unsigned.UInt32.t;
    offidx : Unsigned.UInt32.t;
    nargc : int;
    xargc : int;
    noffs : int;
    enoffidx : Unsigned.UInt32.t;
    nenoffs : int;
  }

  type t = { buffer : Buffer.t; header : header; sections : section array }

  let model h = int_of_char (String.get h.ident Ident.model)
  let encoding h = int_of_char (String.get h.ident Ident.encoding)
  let version h = int_of_char (String.get h.ident Ident.version)
  let difvers h = int_of_char (String.get h.ident Ident.difvers)
  let is_64bit h = Model.is_64bit (model h)
  let _is_little_endian h = Encoding.is_little_endian (encoding h)

  let check_magic ident =
    String.length ident >= 4
    && int_of_char (String.get ident 0) = Magic.mag0
    && int_of_char (String.get ident 1) = Magic.mag1
    && int_of_char (String.get ident 2) = Magic.mag2
    && int_of_char (String.get ident 3) = Magic.mag3

  let parse_header cur =
    let ident = fixed_string cur 16 in
    if not (check_magic ident) then Error "Invalid DOF magic"
    else
      let model_val = int_of_char (String.get ident Ident.model) in
      let _encoding_val = int_of_char (String.get ident Ident.encoding) in
      let is_64 = Model.is_64bit model_val in
      let flags = u32 cur in
      let hdrsize = u32 cur in
      let secsize = u32 cur in
      let secnum = u32 cur in
      let secoff =
        if is_64 then u64 cur else Unsigned.UInt64.of_uint32 (u32 cur)
      in
      let loadsz =
        if is_64 then u64 cur else Unsigned.UInt64.of_uint32 (u32 cur)
      in
      let filesz =
        if is_64 then u64 cur else Unsigned.UInt64.of_uint32 (u32 cur)
      in
      let pad =
        if is_64 then u64 cur else Unsigned.UInt64.of_uint32 (u32 cur)
      in
      Ok { ident; flags; hdrsize; secsize; secnum; secoff; loadsz; filesz; pad }

  let parse_section ~is_64 cur =
    let sect_type = Sect_type.of_int (Unsigned.UInt32.to_int (u32 cur)) in
    let align = u32 cur in
    let flags = u32 cur in
    let entsize = u32 cur in
    let offset =
      if is_64 then u64 cur else Unsigned.UInt64.of_uint32 (u32 cur)
    in
    let size = if is_64 then u64 cur else Unsigned.UInt64.of_uint32 (u32 cur) in
    { sect_type; align; flags; entsize; offset; size }

  let parse_provider cur =
    {
      strtab = u32 cur;
      probes = u32 cur;
      prargs = u32 cur;
      proffs = u32 cur;
      name = u32 cur;
      provattr = u32 cur;
      modattr = u32 cur;
      funcattr = u32 cur;
      nameattr = u32 cur;
      argsattr = u32 cur;
      prenoffs = u32 cur;
    }

  let parse_probe ~is_64 cur =
    let addr = if is_64 then u64 cur else Unsigned.UInt64.of_uint32 (u32 cur) in
    let func = u32 cur in
    let name = u32 cur in
    let nargv = u32 cur in
    let xargv = u32 cur in
    let argidx = u32 cur in
    let offidx = u32 cur in
    let nargc = Unsigned.UInt8.to_int (u8 cur) in
    let xargc = Unsigned.UInt8.to_int (u8 cur) in
    let noffs = Unsigned.UInt16.to_int (u16 cur) in
    let enoffidx = u32 cur in
    let nenoffs = Unsigned.UInt16.to_int (u16 cur) in
    {
      addr;
      func;
      name;
      nargv;
      xargv;
      argidx;
      offidx;
      nargc;
      xargc;
      noffs;
      enoffidx;
      nenoffs;
    }

  let of_buffer buf =
    let cur = Buffer.cursor buf in
    match parse_header cur with
    | Error msg -> Error msg
    | Ok header ->
        let is_64 = is_64bit header in
        let secnum = Unsigned.UInt32.to_int header.secnum in
        let secoff = Unsigned.UInt64.to_int64 header.secoff in
        let sections =
          Array.init secnum (fun i ->
              Buffer.seek cur
                (Int64.to_int secoff
                + (i * Unsigned.UInt32.to_int header.secsize));
              parse_section ~is_64 cur)
        in
        Ok { buffer = buf; header; sections }

  let get_string t ~strtab_idx ~offset =
    if strtab_idx < 0 || strtab_idx >= Array.length t.sections then
      "<invalid strtab>"
    else
      let strtab = t.sections.(strtab_idx) in
      if strtab.sect_type <> Sect_type.Strtab then "<not a strtab>"
      else
        let base = Unsigned.UInt64.to_int64 strtab.offset in
        let start = Int64.to_int base + offset in
        let rec find_nul i =
          if i >= Buffer.size t.buffer then i
          else if t.buffer.{i} = 0 then i
          else find_nul (i + 1)
        in
        let end_pos = find_nul start in
        let len = end_pos - start in
        let result = Bytes.create len in
        for i = 0 to len - 1 do
          Bytes.set result i (Char.chr t.buffer.{start + i})
        done;
        Bytes.to_string result

  let find_sections_by_type t typ =
    Array.to_list t.sections |> List.filter (fun s -> s.sect_type = typ)

  let providers t =
    find_sections_by_type t Sect_type.Provider
    |> List.map (fun sec ->
           let cur = Buffer.cursor t.buffer in
           Buffer.seek cur (Unsigned.UInt64.to_int64 sec.offset |> Int64.to_int);
           let prov = parse_provider cur in
           let name =
             get_string t
               ~strtab_idx:(Unsigned.UInt32.to_int prov.strtab)
               ~offset:(Unsigned.UInt32.to_int prov.name)
           in
           (name, prov, sec))

  let probes_for_provider t (_, prov, _) =
    let probes_idx = Unsigned.UInt32.to_int prov.probes in
    if probes_idx < 0 || probes_idx >= Array.length t.sections then []
    else
      let probes_sec = t.sections.(probes_idx) in
      let entsize = Unsigned.UInt32.to_int probes_sec.entsize in
      if entsize = 0 then []
      else
        let n =
          Unsigned.UInt64.to_int64 probes_sec.size |> Int64.to_int |> fun s ->
          s / entsize
        in
        let cur = Buffer.cursor t.buffer in
        let is_64 = is_64bit t.header in
        List.init n (fun i ->
            let off =
              (Unsigned.UInt64.to_int64 probes_sec.offset |> Int64.to_int)
              + (i * entsize)
            in
            Buffer.seek cur off;
            parse_probe ~is_64 cur)

  let pp_header fmt h =
    Format.fprintf fmt "@[<v 2>DOF Header:@,";
    Format.fprintf fmt "Version: %d@," (version h);
    Format.fprintf fmt "Model: %s@," (Model.to_string (model h));
    Format.fprintf fmt "Encoding: %s@," (Encoding.to_string (encoding h));
    Format.fprintf fmt "DIF Version: %d@," (difvers h);
    Format.fprintf fmt "Header Size: %ld@," (Unsigned.UInt32.to_int32 h.hdrsize);
    Format.fprintf fmt "Section Size: %ld@,"
      (Unsigned.UInt32.to_int32 h.secsize);
    Format.fprintf fmt "Sections: %ld@," (Unsigned.UInt32.to_int32 h.secnum);
    Format.fprintf fmt "Section Offset: 0x%Lx@,"
      (Unsigned.UInt64.to_int64 h.secoff);
    Format.fprintf fmt "Load Size: %Ld@," (Unsigned.UInt64.to_int64 h.loadsz);
    Format.fprintf fmt "File Size: %Ld@]" (Unsigned.UInt64.to_int64 h.filesz)

  let pp_section fmt s =
    let is_loadable =
      Unsigned.UInt32.(logand s.flags (of_int Sect_flags.load) <> zero)
    in
    Format.fprintf fmt "@[<h>%-12s off=0x%08Lx size=%-6Ld align=%-2ld%s@]"
      (Sect_type.to_string s.sect_type)
      (Unsigned.UInt64.to_int64 s.offset)
      (Unsigned.UInt64.to_int64 s.size)
      (Unsigned.UInt32.to_int32 s.align)
      (if is_loadable then " [LOAD]" else "")

  let pp_probe ~get_string fmt p =
    let func_name = get_string (Unsigned.UInt32.to_int p.func) in
    let probe_name = get_string (Unsigned.UInt32.to_int p.name) in
    Format.fprintf fmt "@[<h>%s:%s addr=0x%Lx noffs=%d nargc=%d xargc=%d@]"
      func_name probe_name
      (Unsigned.UInt64.to_int64 p.addr)
      p.noffs p.nargc p.xargc

  let pp fmt t =
    Format.fprintf fmt "@[<v>";
    pp_header fmt t.header;
    Format.fprintf fmt "@,@,@[<v 2>Sections:@,";
    Array.iteri
      (fun i s -> Format.fprintf fmt "[%2d] %a@," i pp_section s)
      t.sections;
    Format.fprintf fmt "@]@,";
    let provs = providers t in
    if provs <> [] then (
      Format.fprintf fmt "@,@[<v 2>Providers:@,";
      List.iter
        (fun ((name, prov, _) as p) ->
          Format.fprintf fmt "@[<v 2>%s:@," name;
          let probes = probes_for_provider t p in
          let strtab_idx = Unsigned.UInt32.to_int prov.strtab in
          let get_string off = get_string t ~strtab_idx ~offset:off in
          List.iter
            (fun probe ->
              Format.fprintf fmt "  %a@," (pp_probe ~get_string) probe)
            probes;
          Format.fprintf fmt "@]")
        provs;
      Format.fprintf fmt "@]");
    Format.fprintf fmt "@]@."

  let dump t = pp Format.std_formatter t
end

let extract_dof_section buffer =
  let _header, commands = Macho.read buffer in
  let rec find_dof_in_commands = function
    | [] -> None
    | Macho.LC_SEGMENT_32 seg_lazy :: rest
    | Macho.LC_SEGMENT_64 seg_lazy :: rest -> (
        let seg = Lazy.force seg_lazy in
        let sections = seg.Macho.seg_sections in
        let dof_sec =
          Array.find_opt
            (fun sec ->
              (sec.Macho.sec_segname = "__DATA"
              || sec.Macho.sec_segname = "__DTRACE"
              || sec.Macho.sec_segname = "__TEXT")
              && (sec.Macho.sec_sectname = "__dof"
                 || sec.Macho.sec_sectname = "__dof_ocaml"))
            sections
        in
        match dof_sec with
        | Some sec -> Some (Macho.section_body buffer sec)
        | None -> find_dof_in_commands rest)
    | _ :: rest -> find_dof_in_commands rest
  in
  find_dof_in_commands commands

let list_probes dof =
  (* Find all probe sections and strtab sections *)
  let probe_secs = DOF.find_sections_by_type dof DOF.Sect_type.Probes in
  let strtab_secs = DOF.find_sections_by_type dof DOF.Sect_type.Strtab in

  (* Use first strtab if available *)
  let strtab_idx =
    match strtab_secs with
    | [] -> -1
    | _ ->
        (* Find index of first strtab in sections array *)
        let rec find_idx i =
          if i >= Array.length dof.DOF.sections then -1
          else if dof.DOF.sections.(i).DOF.sect_type = DOF.Sect_type.Strtab then
            i
          else find_idx (i + 1)
        in
        find_idx 0
  in

  let get_string off = DOF.get_string dof ~strtab_idx ~offset:off in

  (* Process each PROBES section *)
  List.iter
    (fun probes_sec ->
      let entsize = Unsigned.UInt32.to_int probes_sec.DOF.entsize in
      if entsize > 0 then
        let n =
          Unsigned.UInt64.to_int64 probes_sec.DOF.size |> Int64.to_int
          |> fun s -> s / entsize
        in
        let cur = Buffer.cursor dof.DOF.buffer in
        let is_64 = DOF.is_64bit dof.DOF.header in
        for i = 0 to n - 1 do
          let off =
            (Unsigned.UInt64.to_int64 probes_sec.DOF.offset |> Int64.to_int)
            + (i * entsize)
          in
          Buffer.seek cur off;
          let probe = DOF.parse_probe ~is_64 cur in
          let probe_name = get_string (Unsigned.UInt32.to_int probe.DOF.name) in
          Printf.printf "ocaml:%s\n" probe_name
        done)
    probe_secs

let process_file list_only file =
  let buffer = Buffer.parse file in
  if Macho.is_fat buffer then
    let fat_header = Macho.read_fat buffer in
    let arch_to_use =
      if Array.length fat_header.fat_archs > 0 then
        Some fat_header.fat_archs.(0)
      else None
    in
    match arch_to_use with
    | None ->
        Printf.eprintf "No architectures found in fat binary\n";
        `Error (false, "No architectures in fat binary")
    | Some arch -> (
        let arch_buffer = Macho.extract_arch buffer arch in
        match extract_dof_section arch_buffer with
        | None ->
            Printf.printf "No DOF section found in %s\n" file;
            `Ok ()
        | Some dof_buf -> (
            match DOF.of_buffer dof_buf with
            | Error msg ->
                Printf.eprintf "Error parsing DOF: %s\n" msg;
                `Error (false, msg)
            | Ok dof ->
                if list_only then (
                  list_probes dof;
                  `Ok ())
                else (
                  Printf.printf "\nDisplaying DOF section from %s:\n\n" file;
                  DOF.dump dof;
                  `Ok ())))
  else
    match extract_dof_section buffer with
    | None ->
        Printf.printf "No DOF section found in %s\n" file;
        `Ok ()
    | Some dof_buf -> (
        match DOF.of_buffer dof_buf with
        | Error msg ->
            Printf.eprintf "Error parsing DOF: %s\n" msg;
            `Error (false, msg)
        | Ok dof ->
            if list_only then (
              list_probes dof;
              `Ok ())
            else (
              Printf.printf "\nDisplaying DOF section from %s:\n\n" file;
              DOF.dump dof;
              `Ok ()))

let file =
  let doc = "Mach-O binary file to analyze" in
  Arg.(required & pos 0 (some string) None & info [] ~docv:"FILE" ~doc)

let list_probes_flag =
  let doc = "List probe names only (one per line, format: provider:probe)" in
  Arg.(value & flag & info [ "l"; "list-probes" ] ~doc)

let ocdof_t = Term.(ret (const process_file $ list_probes_flag $ file))

let info =
  let doc =
    "display DOF (DTrace Object Format) sections from Mach-O binaries"
  in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Display DTrace probe information from Mach-O binaries. Similar to \
         'readelf -n' for Linux ELF files.";
      `P
        "DOF sections contain DTrace USDT (Userland Statically Defined \
         Tracing) probe definitions.";
    ]
  in
  Cmd.info "ocdof" ~version:"1.0" ~doc ~man

let () = exit (Cmd.eval (Cmd.v info ocdof_t))
