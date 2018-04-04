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
		AND ip_src IS NOT NULL 
		AND ip_dst IS NOT NULL
		AND
			(
				tcp_dstport in [${lrange?c}:${hrange?c}]
				OR
				udp_dstport in [${lrange?c}:${hrange?c}]
			)
		
	).std:groupwin(ip_src, tcp_dstport, udp_dstport)
		.std:unique(ip_dst)
		.win:time_length_batch(${time_window?c} seconds, ${alert_count?c}) 
		GROUP BY ip_src, tcp_dstport, udp_dstport 
		HAVING count(ip_dst) = ${alert_count?c}
	;