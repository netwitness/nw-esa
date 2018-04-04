/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')
@Description('${module_desc}')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst"})
SELECT * FROM
	Event(
		medium = 32 
		AND ec_activity = 'Logon' 
		AND ec_outcome = 'Success'
		AND user_dst IN (<@builduserlist userlist=user_list/>)
		AND logon_type IN ('2','10','11','12') 
		AND device_class = 'Windows Hosts' 
		AND reference_id IN ('4624', '528', '540')
		
	); 


	<#macro builduserlist userlist>
		<@compress single_line=true>
			<#list userlist as u>
				'${u.value}'
				<#if u_has_next>,</#if>	
			</#list>
		</@compress>
	</#macro>