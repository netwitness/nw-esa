/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"device_ip", "device_host"})
	
SELECT * FROM pattern @SuppressOverlappingMatches [

every a=Event (device_type='rsaecat' AND ip_src is not null AND medium=32)
-> b=Event(device_ip = a.ip_src AND device_class = 'Windows Hosts' AND reference_id IN ('517','1102') AND event_source.toLowerCase() IN ('security','microsoft-windows-eventlog') AND medium = 32 AND (device_ip is not null or device_host is not null))

where timer:within(${time_window?c} seconds)
];
