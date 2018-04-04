/*
Version: 3
*/
module ${module_id};

@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"ip_src"})
<#if module_debug>@Audit('stream')</#if>	

SELECT * FROM 
	Event (
		medium = 1
		AND
		service = 53
		AND
		streams = 2
		AND
		ip_src IS NOT NULL
		).std:groupwin(ip_src)
		.win:time_length_batch(${time_window?c} sec, ${alert_count?c}) 
		GROUP BY ip_src 
		HAVING count(*) = ${alert_count?c};
