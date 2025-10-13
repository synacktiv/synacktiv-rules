rule MAL_vGet_ELF_Downloader_Rust_Oct25 {
  meta:
    description = "Detects vGet Downloader, observed to load vShell"
    author = "CSIRT Synacktiv, Théo Letailleur"
    date = "2025-10-13"
    reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
    hash = "0da5a7d302ca5bc15341f9350a130ce46e18b7f06ca0ecf4a1c37b4029667dbb"
    hash = "caa4e64ff25466e482192d4b437bd397159e4c7e22990751d2a4fc18a6d95ee2"
  strings:
    $hc_rust = "RUST_BACKTRACE"  fullword ascii
    $hc_symlink = "/tmp/.del"  fullword ascii
    $hc_proxy = "Proxy-Authorization:"  fullword ascii
    $lc_crypto_chacha = "expand 32-byte k"  fullword ascii
    $lc_pdfuser = "cosmanking"  fullword ascii
    $lc_local = "127.0.0.1" fullword ascii
  condition:
    uint32(0) == 0x464c457f and elf.type == elf.ET_DYN and filesize > 500KB and filesize < 3MB 
    and all of ($hc*)
    and 1 of ($lc*)
}