/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"ip_src", "ip_dst"})

SELECT * FROM Event(
			medium = 32
			AND	ec_activity='Logon' 
			AND	ec_outcome='Failure' 
			AND	ip_src IS NOT NULL
			AND	ip_dst IS NOT NULL
			AND	user_dst IS NOT NULL 
		).std:groupwin(ip_src,ip_dst).win:time_length_batch(${time_window?c} seconds, ${count?c}).std:unique(user_dst) group by ip_src,ip_dst having count(*) = ${count?c};

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"host_src", "host_dst"})
		
SELECT * FROM Event(
			medium = 32
			AND ec_activity='Logon'
			AND	ec_outcome='Failure'
			AND	host_src IS NOT NULL
			AND	host_dst IS NOT NULL
			AND	user_dst IS NOT NULL 
		).std:groupwin(host_src,host_dst).win:time_length_batch(${time_window?c} seconds, ${count?c}).std:unique(user_dst) group by host_src,host_dst having count(*) = ${count?c};