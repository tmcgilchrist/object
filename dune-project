(lang dune 3.9)
(name object)
(generate_opam_files true)

(license MIT)
(maintainers "Tim McGilchrist <timmcgil@gmail.com>")
(authors "Tim McGilchrist <timmcgil@gmail.com>")
(source (github tmcgilchrist/object))

(package
  (name object)
 (tags (elf object mach-o pe coff))
 (synopsis "A unified interface for reading and writing object file formats")
 (description "A unified interface for reading and writing object file formats")
  (depends
    (ocaml (>= 4.08))
    integers
    (cmdliner :with-test)
    (alcotest :with-test)
    (ocamlformat (and :with-dev-setup (= 0.27.0)))))
