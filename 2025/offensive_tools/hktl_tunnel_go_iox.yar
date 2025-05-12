rule SYNACKTIV_HKTL_Tunnel_GO_Iox_May25 : COMMODITY FILE
{
    meta:
        description = "Detects the iox tunneling tool used for port forwarding and SOCKS5 proxy"
        author = "Synacktiv, Maxence Fossat [@cybiosity]"
        id = "407d4f90-a281-4f0c-8d8e-ebe45217d3d9"
        date = "2025-05-12"
        modified = "2025-05-12"
        reference = "https://www.synacktiv.com/en/publications/open-source-toolset-of-an-ivanti-csa-attacker"
        license = "DRL-1.1"
        hash = "0500c9d0b91e62993447cdcf5f691092aff409eca24080ce149f34e48a0445e0"
        hash = "13c1cfb12017aa138e2f8d788dcd867806cc8fd6ae05c3ab7d886c18bcd4c48a"
        hash = "1a9524a2c39e76e0ea85abba1f0ddddc5d0d0a3a601a1b75e8d224ad93968b5e"
        hash = "1bd710dc054716bf5553abd05d282d9aeb7eb30a76320bd6be4ce2efc04b20bc"
        hash = "328570168780a5dd39e1b49db00430c02d3292ff1e8b14ff6aacce40d90d908f"
        hash = "35d83137ea70e94187a9ad9b7fa2d7b6c6b9128eb9d104380f2ac525784b9a78"
        hash = "4806fd64647e02a34dd49f9057c6bf95325dcc923764ff2ef61cbbab40ca8c48"
        hash = "4c4ec3314afe4284e4cf8bf2fdfb402820932ddcf16913a88a2b7c1d55a12a90"
        hash = "4d49ceb20ad85b117dd30f317977526e73cb5dd622705277b5cbc691972abb4b"
        hash = "63d32b6b29e5d4f8aab4b59681d853e481e858cbf1acfcb190469d8881f47aa6"
        hash = "92cc697b909c398de8533499271c9d3c2425a71feaa0d70bac7428d90423ddff"
        hash = "9480d060de29548bcf961267cec1e8c926b99dc93b65fd696bbedd308ad9f85f"
        hash = "a4139ffd12565edf5291dc5580a70e600f76695b03376e5c0130ade18a6a7bcd"
        hash = "aeddd8240c09777a84bb24b5be98e9f5465dc7638bec41fb67bbc209c3960ae1"
        hash = "b9c40960259b9b14d80c8b1cb3438913f8550fe56dbdfe314b53c7ceae77ccb0"
        hash = "ba661b3f18fa7865503523ce514367e05626c088a34c6c29269e3bde57d00ec3"
        hash = "c061952d49f03acf9e464ab927b0b6b3bc38da8caaf077e70ace77116b6d1b8c"
        hash = "c1ca82411e293ec5d16a8f81ed9466972a8ead23bd4080aaf9505baccce575ba"
        hash = "c6cf82919b809967d9d90ea73772a8aa1c1eb3bc59252d977500f64f1a0d6731"
        hash = "c8b40fbb5cd27f42c143c35b67c700f7ea42a2084418c5e2da82fb0ac094f966"
        hash = "cd5bbcf663f06003637e4aab348bbec3d4a47e53e8fa85826e161d34b86e93f8"
        hash = "d879ff9275cd62f4e7935261e17461d3a3cd1a29d65a5688bd382c47ae680ad6"
        hash = "e92c85b36d0848171ada787862413e0edd8291c8ae6a43e13b075b9ccbd53434"
        hash = "f22f2932c02bbd47ea556e15a51c20301ca7084c4b943672ade70bc49dc3e0c4"
        score = 75
        tags = "COMMODITY, FILE"
        tlp = "TLP:CLEAR"
        pap = "PAP:CLEAR"

    strings:
        $s1 = "Forward UDP traffic between %s (encrypted: %v) and %s (encrypted: %v)"
        $s2 = "Open pipe: %s <== FWD ==> %s"
        $s3 = "Reverse socks5 server handshake ok from %s (encrypted: %v)"
        $s4 = "Recv exit signal from remote, exit now"
        $s5 = "socks consult transfer mode or parse target: %s"

    condition:
        ( uint16be( 0 ) == 0x4d5a or uint32be( 0 ) == 0x7f454c46 or uint32be( 0 ) == 0xcffaedfe or uint32be(0) == 0xcefaedfe ) and filesize < 5MB and all of them
}
