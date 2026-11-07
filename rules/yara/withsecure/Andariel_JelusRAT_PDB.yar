
import "pe"
rule Andariel_JelusRAT_PDB
{
    meta:
        score = 75
        author = "WithSecure"
        description = "Detects JelusRAT packer and payload samples via PDB path"
    strings:
        $str_pdb = /jelus *rat[\x20-\x7F]{0,100}\.pdb\x00/ nocase
    condition:
        // max 16 MB
        filesize <= 16MB
        // MZ
        and uint16(0) == 0x5A4D
        // PE
        and (uint32(uint32(0x3C)) == 0x00004550)
        // PDB path
        and all of them
}
