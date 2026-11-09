rule BinSight_Demo_PasswordMarker
{
    meta:
        description = "Demo strings-only rule for BinSight /Yara fallback"
    strings:
        $a = "password="
    condition:
        $a
}
