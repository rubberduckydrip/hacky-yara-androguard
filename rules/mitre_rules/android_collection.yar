/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule sms_messages_a : android_collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather SMS messages. "
        reference = "https://attack.mitre.org/techniques/T1636/004/"

    strings:
        $string_a = "android.permission.READ_SMS"

    condition:
        any of them
}


rule sms_messages_b : android_collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather SMS messages. "

    strings:
        $string_a = "content://sms/"

    condition:
        any of them
}

rule call_log_a : android_collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather call log data."
        reference = "https://attack.mitre.org/techniques/T1636/002/"

    strings:
        $string_a = "android.permission.READ_CALL_LOG"

    condition:
        any of them
}

rule call_log_b : android_collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather call log data."
        reference = "https://attack.mitre.org/techniques/T1636/002/"

    strings:
        $string_a = "CallLog.Calls.CONTENT_URI"

    condition:
        any of them
}


rule contacts_a : android_collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather contact list data."
        reference = "https://attack.mitre.org/techniques/T1636/003/"

    strings:
        $string_a = "android.permission.READ_CONTACTS"

    condition:
        any of them
}

rule contacts_b : android_collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather contact list data."
        reference = "https://attack.mitre.org/techniques/T1636/003/"

    strings:
        $string_a = "ContactsContract.Contacts.CONTENT_URI"

    condition:
        any of them
}
