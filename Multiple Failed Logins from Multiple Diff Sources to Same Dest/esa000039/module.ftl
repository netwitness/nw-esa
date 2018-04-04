/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst", "ip_dst"})

SELECT * FROM  Event(
				medium = 32 
				AND ec_activity='Logon' 
				AND ec_outcome='Failure'
				AND ip_src IS NOT NULL 
				AND ip_dst IS NOT NULL
				AND user_dst IS NOT NULL 
		).std:groupwin(user_dst,ip_dst).win:time_length_batch(${time_window?c} seconds, ${count?c}).std:unique(ip_src) group by user_dst,ip_dst having count(*) = ${count?c};

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst", "host_dst"})
		
SELECT * FROM  Event(
			medium = 32
			AND ec_activity='Logon' 
			AND ec_outcome='Failure'
			AND	host_src IS NOT NULL 
			AND	host_dst IS NOT NULL
			AND	user_dst IS NOT NULL 
		).std:groupwin(user_dst,host_dst).win:time_length_batch(${time_window?c} seconds, ${count?c}).std:unique(host_src) group by user_dst,host_dst having count(*) = ${count?c};
			