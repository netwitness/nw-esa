/*
Version: 3
*/

module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c})


SELECT * FROM PATTERN @SuppressOverlappingMatches 
[
	EVERY
	a=Event (medium = 1 AND country_src!='${home_country}' AND ip_src IS NOT NULL AND ip_dst IS NOT NULL)
	->
	b=Event (medium = 32 AND event_desc LIKE ('%entered promiscuous mode%') AND device_ip IS NOT NULL AND device_ip = a.ip_dst)
	WHERE timer:within(${time_window?c} seconds)
];
