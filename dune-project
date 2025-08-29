(lang dune 3.0)
(name object)
(generate_opam_files true)

(license MIT)

(package
  (name object)
  (depends
    (ocaml (>= 4.08))
    (cmdliner :with-test))
  (synopsis "A unified interface for reading and writing object file formats")
  (description "A unified interface for reading and writing object file formats"))