/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst"})
select * from Event(
		  device_class = 'Windows Hosts' 
		  and reference_id IN ('517','1102')
		  and medium = 32
		  and (device_ip is not null or device_host is not null)

  		).std:groupwin(user_dst).win:time_length_batch(${time_window?c} sec, ${count?c}).std:unique(device_ip, device_host )
		group by user_dst 
		having count(*) = ${count?c}
		;
