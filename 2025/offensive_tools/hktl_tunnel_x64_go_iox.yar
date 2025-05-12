rule SYNACKTIV_HKTL_Tunnel_X64_GO_Iox_May25 : COMMODITY FILE
{
    meta:
        description = "Detects the 64-bits version of the iox tunneling tool used for port forwarding and SOCKS5 proxy"
        author = "Synacktiv, Maxence Fossat [@cybiosity]"
        id = "0b5a4689-58ea-45d5-aa14-a1455276352a"
        date = "2025-05-12"
        modified = "2025-05-12"
        reference = "https://www.synacktiv.com/en/publications/open-source-toolset-of-an-ivanti-csa-attacker"
        license = "DRL-1.1"
        hash = "0500c9d0b91e62993447cdcf5f691092aff409eca24080ce149f34e48a0445e0"
        hash = "13c1cfb12017aa138e2f8d788dcd867806cc8fd6ae05c3ab7d886c18bcd4c48a"
        hash = "1a9524a2c39e76e0ea85abba1f0ddddc5d0d0a3a601a1b75e8d224ad93968b5e"
        hash = "1bd710dc054716bf5553abd05d282d9aeb7eb30a76320bd6be4ce2efc04b20bc"
        hash = "2457a3241ec13c77b4132d6c5923e63b51a4d05a96dc0ae249c92a43ed9c7c04"
        hash = "328570168780a5dd39e1b49db00430c02d3292ff1e8b14ff6aacce40d90d908f"
        hash = "39d51ef91e189de44696ac67590b4251a6a320719668399127096dc57cbecba3"
        hash = "4c4ec3314afe4284e4cf8bf2fdfb402820932ddcf16913a88a2b7c1d55a12a90"
        hash = "4d1e87b372af0f52b9e2d7a2ac1d223575d29de5e3c0570a96b0d2ff346214f0"
        hash = "4d49ceb20ad85b117dd30f317977526e73cb5dd622705277b5cbc691972abb4b"
        hash = "5138090aee794a08de4b0482bbe58adbd918467d14dedf51961963b324e63f89"
        hash = "63d32b6b29e5d4f8aab4b59681d853e481e858cbf1acfcb190469d8881f47aa6"
        hash = "79d6dfacfa0e0e5bc48d8d894dae261b9412b9c04a39b6ebf992cb8a5a40de95"
        hash = "82aec8846232a43a77e2b5c5a80de523b2c7f912d60bce3ac28242156395b9d0"
        hash = "92cc697b909c398de8533499271c9d3c2425a71feaa0d70bac7428d90423ddff"
        hash = "9e3cba612d5f69e27534e3d2ceb7bb6067d44ac93e5b1e74bf994a94dfd706b6"
        hash = "a4139ffd12565edf5291dc5580a70e600f76695b03376e5c0130ade18a6a7bcd"
        hash = "a8bda8e1d39ee61998381a2f0bfeb7069b19035551b8895eb48642bf98ade3d1"
        hash = "aeddd8240c09777a84bb24b5be98e9f5465dc7638bec41fb67bbc209c3960ae1"
        hash = "b9c40960259b9b14d80c8b1cb3438913f8550fe56dbdfe314b53c7ceae77ccb0"
        hash = "c061952d49f03acf9e464ab927b0b6b3bc38da8caaf077e70ace77116b6d1b8c"
        hash = "c1ca82411e293ec5d16a8f81ed9466972a8ead23bd4080aaf9505baccce575ba"
        hash = "c6cf82919b809967d9d90ea73772a8aa1c1eb3bc59252d977500f64f1a0d6731"
        hash = "c8b40fbb5cd27f42c143c35b67c700f7ea42a2084418c5e2da82fb0ac094f966"
        hash = "d3190648bc428640a721b7d3c2b05c56e855355e8b44561e3b701e80e97f7ea7"
        hash = "d879ff9275cd62f4e7935261e17461d3a3cd1a29d65a5688bd382c47ae680ad6"
        hash = "d9e868af5567a8c823f48f0f30440f1a9d77b52b2e6d785e116c450c48df9fc6"
        score = 75
        tags = "COMMODITY, FILE"
        tlp = "TLP:CLEAR"
        pap = "PAP:CLEAR"

    strings:

        /*
        00000000004BFA73  48 8B 9C 24 88 00 00 00        mov    rbx, [rsp+88h]
        00000000004BFA7B  48 83 FB 20                    cmp    rbx, 20h
        00000000004BFA7F  0F 8D 87 02 00 00              jge    loc_4BFD0C
        00000000004BFA85  48 89 DE                       mov    rsi, rbx
        00000000004BFA88  48 83 E3 1F                    and    rbx, 1Fh
        00000000004BFA8C  83 C3 E0                       add    ebx, 0FFFFFFE0h
        00000000004BFA8F  F7 DB                          neg    ebx
        */
        $expand_key = {
            ( 48 8B 84 24 | 48 8B 9C 24 | 48 8B 8C 24 | 48 8B BC 24 | 48 8B B4 24 | 4C 8B 84 24 | 4C 8B 8C 24 | 4C 8B 94 24 | 4C 8B 9C 24 ) ?? ?? ?? ??
            ( 48 83 F8 20 | 48 83 FB 20 | 48 83 F9 20 | 48 83 FF 20 | 48 83 FE 20 | 49 83 F8 20 | 49 83 F9 20 | 49 83 FA 20 | 49 83 FB 20 )
            ( 0F 8D ?? ?? ?? ?? | 7D ?? )
            ( 48 89 ?? | 49 89 ?? | 4C 89 ?? | 4D 89 ?? )
            ( 48 83 E0 1F | 48 83 E3 1F | 48 83 E1 1F | 48 83 E7 1F | 48 83 E6 1F | 49 83 E0 1F | 49 83 E1 1F | 49 83 E2 1F | 49 83 E3 1F | 83 E0 1F | 83 E3 1F | 83 E1 1F | 83 E7 1F | 83 E6 1F | 41 83 E0 1F | 41 83 E1 1F | 41 83 E2 1F | 41 83 E3 1F )
            ( 83 C0 E0 | 83 C3 E0 | 83 C1 E0 | 83 C7 E0 | 83 C6 E0 | 41 83 C0 E0 | 41 83 C1 E0 | 41 83 C2 E0 | 41 83 C3 E0 )
            ( F7 D8 | F7 DB | F7 D9 | F7 DF | F7 DE | 41 F7 D8 | 41 F7 D9 | 41 F7 DA | 41 F7 DB )
        }

        /*
        00000000004BF92C  44 0F B6 0C 07                 movzx  r9d, byte ptr [rdi+rax]
        00000000004BF931  45 0F AF C8                    imul   r9d, r8d
        00000000004BF935  41 BA FF FF FF FF              mov    r10d, 0FFFFFFFFh
        00000000004BF93B  45 0F B6 DA                    movzx  r11d, r10b
        00000000004BF93F  41 0F B6 C1                    movzx  eax, r9b
        00000000004BF943  41 89 D1                       mov    r9d, edx
        00000000004BF946  31 D2                          xor    edx, edx
        00000000004BF948  66 41 F7 F3                    div    r11w
        00000000004BF94C  41 0F AF D1                    imul   edx, r9d
        00000000004BF950  31 CA                          xor    edx, ecx
        00000000004BF952  41 31 D0                       xor    r8d, edx
        00000000004BF955  44 88 04 0F                    mov    [rdi+rcx], r8b
        */
        $shuffle = {
            ( 44 0F B6 04 | 44 0F B6 0C | 44 0F B6 14 | 44 0F B6 1C | 44 0F B6 44 | 44 0F B6 4C | 44 0F B6 54 | 44 0F B6 5C | 46 0F B6 04 | 46 0F B6 0C | 46 0F B6 14 | 46 0F B6 1C | 46 0F B6 44 | 46 0F B6 4C | 46 0F B6 54 | 46 0F B6 5C ) [1-2]
            ( 45 0F AF C0 | 45 0F AF C1 | 45 0F AF C2 | 45 0F AF C3 | 45 0F AF C8 | 45 0F AF C9 | 45 0F AF CA | 45 0F AF CB | 45 0F AF D0 | 45 0F AF D1 | 45 0F AF D2 | 45 0F AF D3 | 45 0F AF D8 | 45 0F AF D9 | 45 0F AF DA | 45 0F AF DB | 44 0F AF C0 | 44 0F AF C1 | 44 0F AF C2 | 44 0F AF C3 | 44 0F AF C8 | 44 0F AF C9 | 44 0F AF CA | 44 0F AF CB | 44 0F AF D0 | 44 0F AF D1 | 44 0F AF D2 | 44 0F AF D3 | 44 0F AF D8 | 44 0F AF D9 | 44 0F AF DA | 44 0F AF DB )
            [0-4]
            ( 41 B8 | 41 B9 | 41 BA | 41 BB ) FF FF FF FF
            ( 45 0F B6 C0 | 45 0F B6 C1 | 45 0F B6 C2 | 45 0F B6 C3 | 45 0F B6 C8 | 45 0F B6 C9 | 45 0F B6 CA | 45 0F B6 CB | 45 0F B6 D0 | 45 0F B6 D1 | 45 0F B6 D2 | 45 0F B6 D3 | 45 0F B6 D8 | 45 0F B6 D9 | 45 0F B6 DA | 45 0F B6 DB )
            [0-4]
            ( 41 89 D0 | 41 89 D1 | 41 89 D2 | 41 89 D3 | 89 D0 | 89 D1 | 89 D2 | 89 D3 )
            31 D2
            ( 66 41 F7 F0 | 66 41 F7 F1 | 66 41 F7 F2 | 66 41 F7 F3 )
            ( 41 0F AF D0 | 41 0F AF D1 | 41 0F AF D2 | 41 0F AF D3 | 44 0F AF C2 | 44 0F AF CA | 44 0F AF D2 | 44 0F AF DA | 0F AF D0 | 0F AF D1 | 0F AF D2 | 0F AF D3 | 0F AF C2 | 0F AF CA | 0F AF D2 | 0F AF DA )
            ( 31 ?? | 41 31 ?? | 44 31 ?? | 45 31 ?? )
            ( 31 ?? | 41 31 ?? | 44 31 ?? | 45 31 ?? )
            ( 44 88 04 ?F | 44 88 0C ?F | 44 88 14 ?F | 44 88 1C ?F | 44 88 04 ?7 | 44 88 0C ?7 | 44 88 14 ?7 | 44 88 1C ?7 | 88 04 ?F | 88 0C ?F | 88 14 ?F | 88 1C ?F | 88 04 ?7 | 88 0C ?7 | 88 14 ?7 | 88 1C ?7 | 44 88 04 3? | 44 88 0C 3? | 44 88 14 3? | 44 88 1C 3? | 88 04 3? | 88 0C 3? | 88 14 3? | 88 1C 3? )
        }

    condition:
        ( uint16be( 0 ) == 0x4d5a or uint32be( 0 ) == 0x7f454c46 or uint32be( 0 ) == 0xcffaedfe ) and filesize < 5MB and all of them
}
