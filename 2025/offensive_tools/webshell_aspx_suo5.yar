rule SYNACKTIV_WEBSHELL_ASPX_Suo5_May25 : WEBSHELL COMMODITY FILE
{
    meta:
        description = "Detects the .NET version of the suo5 webshell"
        author = "Synacktiv, Maxence Fossat [@cybiosity]"
        id = "d30a7232-f00b-45ab-9419-f43b1611445a"
        date = "2025-05-12"
        modified = "2025-05-12"
        reference = "https://www.synacktiv.com/en/publications/open-source-toolset-of-an-ivanti-csa-attacker"
        license = "DRL-1.1"
        hash = "06710575d20cacd123f83eb82994879367e07f267e821873bf93f4db6312a97b"
        hash = "e6979d7df0876679fc2481aa68fcec5b6ddc82d854f63da2bddb674064384f9a"
        hash = "3bbbef1b4ead98c61fba60dd6291fe1ff08f5eac54d820e47c38d348e4a7b1ec"
        hash = "345c383dd439eb523b01e1087a0866e13f04ff53bb8cc11f3c70b4a382f10c7e"
        hash = "838840dd76ff34cee45996fdc9a87856c9a0f14138e65cb9eb6603ed157d1515"
        hash = "d9657ac8dd562bdd39e8fcc1fff37ddced10f7f3f118d9cd4da6118a223dcc45"
        score = 75
        tags = "WEBSHELL, COMMODITY, FILE"
        tlp = "TLP:CLEAR"
        pap = "PAP:CLEAR"

    strings:
        $user_agent = ".Equals(\"Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.1.2.3\")" ascii    // default User-Agent
        $header = "Response.AddHeader(\"X-Accel-Buffering\", \"no\")" ascii    // X-Accel-Buffering response header
        $xor = /= \(byte\)\(\w{1,1023}\[\w{1,1023}\] \^ \w{1,1023}\);/    // XOR operation

        // suspicious functions
        $s1 = "Request.Headers.Get(\"User-Agent\")" ascii
        $s2 = "if (Request.ContentType.Equals(\"application/plain\"))" ascii
        $s3 = "Response.ContentType = \"application/octet-stream\";" ascii
        $s4 = "= Request.BinaryRead(Request.ContentLength);" ascii
        $s5 = "= Response.OutputStream;" ascii
        $s6 = "new TcpClient()" ascii
        $s7 = ".BeginConnect(" ascii
        $s8 = ".GetStream().Write(" ascii
        $s9 = "new BinaryWriter(" ascii
        $s10 = "new BinaryReader(" ascii
        $s11 = ".ReadBytes(4)" ascii
        $s12 = "BitConverter.GetBytes((Int32)" ascii
        $s13 = "BitConverter.ToInt32(" ascii
        $s14 = "Array.Reverse(" ascii
        $s15 = "new Random().NextBytes(" ascii

    condition:
        filesize < 100KB and ( $user_agent or ( ( $header or $xor ) and 8 of ( $s* ) ) or 12 of ( $s* ) )
}
