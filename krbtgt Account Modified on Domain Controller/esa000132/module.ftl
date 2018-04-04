/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"device_ip", "device_host"})

SELECT * FROM  
			Event(
				ec_activity='Modify' 
			AND 
				ec_outcome='Success' 
			AND
				ec_subject in ('User','Password','Group')
			AND
				user_src IS NOT NULL 
   			AND 
				user_src.toLowerCase().contains('krbtgt')
			AND 
				device_class = 'Windows Hosts' 
			AND
				(		device_ip in  (<@buildIPlist iplist=ip_list/>) 
					OR	
						device_host in (<@buildHostlist hostlist=host_list/>)
				)
			AND
			medium=32
		
			).win:time_length_batch(${time_window?c} seconds, ${count?c}) having count(*) = ${count?c};

<#macro buildIPlist iplist>
	<@compress single_line=true>
	<#list iplist as v>
		<@buildScalar value=v/>
		<#if v_has_next>,</#if>	
	</#list>
	</@compress>
</#macro>

<#macro buildHostlist hostlist>
	<@compress single_line=true>
	<#list hostlist as v>
		<@buildScalar value=v/>
		<#if v_has_next>,</#if>	
	</#list>
	</@compress>
</#macro>

<#macro buildScalar value>
	<#if value.type?starts_with("string")>
		'${value.value}'
	<#elseif value.type?starts_with("short") || value.type?starts_with("integer") 
		|| value.type?starts_with("long") || value.type?starts_with("float") || value.type?starts_with("int")>
		${value.value?c}	
	</#if>
</#macro>