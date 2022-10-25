import "androguard"

rule AndroRAT
{
    meta:
        description = "Rule to catch AndroRAT"
    condition:
        androguard.package_name("com.example.reverseshell2")
         and androguard.permissions_number >= 16 
}
