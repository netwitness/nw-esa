/*
Version: 2
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')
@Description('${module_desc}')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst"})

SELECT * FROM  
			Event(
				ec_activity='Logon' 
			AND 
				ip_dst IS NOT NULL
			AND 
				user_dst IS NOT NULL 
			).std:groupwin(user_dst).win:time_length_batch(${time_window?c} seconds, ${count?c}).std:unique(ip_dst) group by user_dst having count(*) = ${count?c};

@Name('${module_id}_Alert')
@Description('${module_desc}')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst"})
		
SELECT * FROM  
			Event(
				ec_activity='Logon' 
			AND 
				host_dst IS NOT NULL
			AND
				user_dst IS NOT NULL 
			).std:groupwin(user_dst).win:time_length_batch(${time_window?c} seconds, ${count?c}).std:unique(host_dst) group by user_dst having count(*) = ${count?c};