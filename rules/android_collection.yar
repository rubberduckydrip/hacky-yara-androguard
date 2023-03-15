/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule access_notification__android_collection
{
	meta:
		description = "Adversaries may collect data within notifications sent by the operating system or other applications"
        reference = "https://attack.mitre.org/techniques/T1517/"

	strings:
		$string_a = "BIND_NOTIFICATION_LISTENER_SERVICE"

	condition:
		any of them
}

rule clipboard_data__android_collection
{
    meta:
        description = "Adversaries may abuse clipboard manager APIs to obtain sensitive information copied to the device clipboard"
        reference = "https://attack.mitre.org/techniques/T1414/"

    strings:
        $string_a = "ClipboardManager.OnPrimaryClipChangedListener"

    condition:
        any of them
}

rule keylogging__android_collection
{
    meta:
        description = "Adversaries may log user keystrokes to intercept credentials or other information from the user as the user types them"
        reference = "https://attack.mitre.org/techniques/T1417/001/"

    strings:
        $string_a = "onAccessibilityEvent"
        $string_b = "AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED"

    condition:
        any of them
}

rule gui_input_capture__android_collection

{
    meta:
        description = "Adversaries may mimic common operating system GUI components to prompt users for sensitive information with a seemingly legitimate prompt"
        reference = "https://attack.mitre.org/techniques/T1417/002/"

    strings:
        $string_a = "android.permission.SYSTEM_ALERT_WINDOW"

    condition:
        any of them
}


rule audio_capture__android_collection
{
	meta:
		description = "Adversaries may capture audio to collect information by leveraging standard operating system APIs of a mobile device"
        reference = "https://attack.mitre.org/techniques/T1429/"

	strings:
        $string_a = "RECORD_AUDIO"
        $string_b = "CAPTURE_AUDIO_OUTPUT"

	condition:
		any of them
}


rule data_from_local_system__android_collection
{
    meta: 
        description = "Adversaries may search local system sources, such as file systems or local databases, to find files of interest and sensitive data prior to exfiltration"
        resource = "https://attack.mitre.org/techniques/T1533/"
        resource_code = "https://developer.android.com/training/data-storage"

    strings:
        $string_a = "READ_EXTERNAL_STORAGE"
        $string_b = "WRITE_EXTERNAL_STORAGE"
        $string_c = "MANAGE_EXTERNAL_STORAGE"
        $string_d = "MediaStore"

    condition:
        any of them
}

rule calendar_entries__android_collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather calendar entry data. On Android, this can be accomplished using the Calendar Content Provider"
        reference = "https://attack.mitre.org/techniques/T1636/001/"

    strings:
        $string_a = "android.permission.READ_CALENDAR"
        $string_b = "android.permission.WRITE_CALENDAR"

    condition:
        any of them
}

rule call_log__android_collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather call log data. On Android, this can be accomplished using the Call Log Content Provider"
        reference = "https://attack.mitre.org/techniques/T1636/002/"

    strings:
        $string_a = "android.permission.READ_CALL_LOG"

    condition:
        any of them
}

rule contacts__android_collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather contact list data"
        reference = "https://attack.mitre.org/techniques/T1636/003/"

    strings:
        $string_a = "android.permission.READ_CONTACTS"

    condition:
        any of them
}

rule sms_messages__android_collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather SMS messages. "
        reference = "https://attack.mitre.org/techniques/T1636/004/"

    strings:
        $string_a = "android.permission.READ_SMS"

    condition:
        any of them
}

rule screen_capture__android_collection
{
    meta: 
        description = "Adversaries may use screen capture to collect additional information about a target device, such as applications running in the foreground, user data, credentials, or other sensitive information"
        reference = "https://attack.mitre.org/techniques/T1513/"

    strings:
        $string_a = "MediaProjectionManager"

    condition:
        any of them
}

rule video_capture__android_collection
{
    meta: 
        description =  "An adversary can leverage a device’s cameras to gather information by capturing video recordings"
        reference = "https://attack.mitre.org/techniques/T1512/"

    strings:
        $string_a = "android.permission.CAMERA"

    condition:
        any of them
}


