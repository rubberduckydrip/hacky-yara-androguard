/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule access_notification : collection credential_access
{
	meta:
		description = "Adversaries may collect data within notifications sent by the operating system or other applications"
        reference = "https://attack.mitre.org/techniques/T1517/"

	strings:
		$string_a = "BIND_NOTIFICATION_LISTENER_SERVICE"

	condition:
		any of them
}

rule clipboard_data : collection credential_access
{
    meta:
        description = "Adversaries may abuse clipboard manager APIs to obtain sensitive information copied to the device clipboard"
        reference = "https://attack.mitre.org/techniques/T1414/"

    strings:
        $string_a = "ClipboardManager.OnPrimaryClipChangedListener"

    condition:
        any of them
}

rule keylogging : collection credential_access
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

rule gui_input_capture : collection credential_access

{
    meta:
        description = "Adversaries may mimic common operating system GUI components to prompt users for sensitive information with a seemingly legitimate prompt"
        reference = "https://attack.mitre.org/techniques/T1417/002/"

    strings:
        $string_a = "android.permission.SYSTEM_ALERT_WINDOW"

    condition:
        any of them
}


rule audio_capture : collection
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


rule data_from_local_system : collection
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

rule calendar_entries : collection
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

rule call_log : collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather call log data. On Android, this can be accomplished using the Call Log Content Provider"
        reference = "https://attack.mitre.org/techniques/T1636/002/"

    strings:
        $string_a = "android.permission.READ_CALL_LOG"

    condition:
        any of them
}

rule contacts : collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather contact list data"
        reference = "https://attack.mitre.org/techniques/T1636/003/"

    strings:
        $string_a = "android.permission.READ_CONTACTS"

    condition:
        any of them
}

rule sms_messages : collection
{
    meta:
        description = "Adversaries may utilize standard operating system APIs to gather SMS messages. "
        reference = "https://attack.mitre.org/techniques/T1636/004/"

    strings:
        $string_a = "android.permission.READ_SMS"

    condition:
        any of them
}

rule screen_capture : collection
{
    meta: 
        description = "Adversaries may use screen capture to collect additional information about a target device, such as applications running in the foreground, user data, credentials, or other sensitive information"
        reference = "https://attack.mitre.org/techniques/T1513/"

    strings:
        $string_a = "MediaProjectionManager"

    condition:
        any of them
}

rule video_capture : collection
{
    meta: 
        description =  "An adversary can leverage a device’s cameras to gather information by capturing video recordings"
        reference = "https://attack.mitre.org/techniques/T1512/"

    strings:
        $string_a = "android.permission.CAMERA"

    condition:
        any of them
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule dynamic_code_loading : defence_evasion
{
	meta:
		description = "Adversaries may download and execute dynamic code not included in the original application package after installation"
        reference = "https://attack.mitre.org/techniques/T1407/"

	strings:
        $string_a = "DexClassLoader"
        $string_b = "System.load"
        $string_c = "JavaScriptInterface"

	condition:
		any of them
}

rule execution_guardrails : defence_evasion
{
    meta:
        description = "Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target"
        reference = "https://attack.mitre.org/techniques/T1627/"

    strings:
        $strings_a = "SystemProperties"
        $strings_b = "Build.MODEL"
        $strings_c = "Build.HARDWARE"
        $strings_d = "Build.PRODUCT"

    condition:
        any of them
}

rule geofencing : defence_evasion
{
    meta:
        description = "Adversaries may use a device’s geographical location to limit certain malicious behaviors"
        reference = "https://attack.mitre.org/techniques/T1627/001/"

    strings:
        $string_a = "ACCESS_FINE_LOCATION"
        $string_b = "ACCESS_BACKGROUND_LOCATION"

    condition:
        any of them
}

rule suppress_application : defence_evasion
{
    meta:
        description = "A malicious application could suppress its icon from being displayed to the user in the application launcher"
        reference = "https://attack.mitre.org/techniques/T1628/001/"
        reference_code = "https://stackoverflow.com/questions/19114439/android-hide-unhide-app-icon-programmatically"

    strings:
        $string_a = "android.intent.category.LEANBACK_LAUNCHER"
        $string_b = "COMPONENT_ENABLED_STATE_DISABLED"

    condition: 
        any of them
}

rule user_evasion : defence_evasion
{
    meta: 
        description = "By utilizing the various motion sensors on a device, such as accelerometer or gyroscope, an application could detect that the device is being interacted with"
        reference = "https://attack.mitre.org/techniques/T1628/002/"
        
    strings:
        $string_a = "SensorManager"
      
    condition:
        all of them
}

rule device_lockout : defence_evasion
{
    meta:
        description = "An adversary may seek to inhibit user interaction by locking the legitimate user out of the device"
        reference = "https://attack.mitre.org/techniques/T1629/002/"

    strings:
        $string_a = "DevicePolicyManager.lockNow"

    condition:
        all of them
}

rule uninstall_malicious_application : defence_evasion
{
    meta:
        description = "Adversaries may include functionality in malware that uninstalls the malicious application from the device"
        reference = "https://attack.mitre.org/techniques/T1630/001/"
        referense_code = "https://stackoverflow.com/questions/6813322/install-uninstall-apks-programmatically-packagemanager-vs-intents"

    strings:
        $string_a = "REQUEST_DELETE_PACKAGES"

    condition:
        all of them
}

rule file_deletion : defence_evasion
{
    meta: 
        description = "Adversaries may wipe a device or delete individual files in order to manipulate external outcomes or hide activity"
        reference = "https://attack.mitre.org/techniques/T1630/002/"
        reference_code = "https://stackoverflow.com/questions/24659704/how-do-i-delete-files-programmatically-on-android"

    strings:
        $string_a = ".delete()"

    condition:
        all of them
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule sms_control : impact
{
	meta:
		description = "Adversaries may delete, alter, or send SMS messages without user authorization"
        reference = "https://attack.mitre.org/techniques/T1582/"

	strings:
        $string_a = "RECEIVE_SMS"
        $string_b = "SEND_SMS"
		$string_c = "SMS_DELIVER"

	condition:
		any of them
}

rule call_control : impact collection c2
{
    meta:
        description = "Adversaries may make, forward, or block phone calls without user authorization. "
        reference = "https://attack.mitre.org/techniques/T1616/"

    strings:
        $string_a = "ANSWER_PHONE_CALLS"
        $string_b = "CALL_PHONE"
        $string_c = "PROCESS_OUTGOING_CALLS"
        $string_d = "MANAGE_OWN_CALLS"
        $string_e = "ConnectionService"
        $string_f = "BIND_TELECOM_CONNECTION_SERVICE"
        $string_g = "WRITE_CALL_LOG"

    condition: 
        any of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule event_triggered_execution_broadcast_receivers : persistance
{
	meta:
		description = "Adversaries may establish persistence using system mechanisms that trigger execution based on specific events"
        reference = "https://attack.mitre.org/techniques/T1624/001/"

	strings:
        $string_a = "BOOT_COMPLETED"
		$string_c = "USER_PRESENT"
        $string_d = "SCREEN_ON"

	condition:
		any of them
}

rule foreground_persistance : persistance
{
    meta:
        description = "Adversaries may abuse Android's startForeground() API method to maintain continuous sensor access"
        reference = "https://attack.mitre.org/techniques/T1624/001/"

    strings:
        $string_a = "startForeground"

    condition:
        any of them
}

