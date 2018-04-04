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
				user_dst IS NOT NULL 
   			AND 
			user_dst IN (<@builduserlist userlist=user_list/>)
		
			).std:groupwin(user_dst).win:time_length_batch(${time_window?c} seconds, ${count?c}).std:unique(device_ip,device_host) group by user_dst having count(*) = ${count?c};


<#macro builduserlist userlist>
	<@compress single_line=true>
		<#list userlist as u>
			'${u.value}'
			<#if u_has_next>,</#if>	
		</#list>
	</@compress>
</#macro>	