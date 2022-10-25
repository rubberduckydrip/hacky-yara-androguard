import "androguard"

rule Permisison_Abuse
{
    meta:
        description = "Rule to catch tom much permissions"
    condition:
         androguard.permissions_number >= 16
}

rule Device_Behaviour_Tracking
{
    meta:
        description = "Rule top catch apps that track booting"
    condition:
        androguard.filter("android.intent.action.BOOT_COMPLETED") or
        androguard.filter(/android.intent.action.SCREEN*/)
}
