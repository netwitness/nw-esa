/*
Description: This rule is triggered when a user enters Guest credentials to log in to a domain controller and fails multiple times within a certain number of minutes. The default is 3 failures within 3 minutes.

There are five parameters:
Device hostnames to monitor
Device IP addresses to monitor
Guest usernames to monitor
Number of failures
Number of minutes

Version: 2
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"device_ip", "device_host"})
SELECT * FROM
	Event(
		ec_activity = 'Logon' 
		AND 
		ec_outcome = 'Failure'
		AND 
		(
		<#if username_contains?size &gt; 0>
				<@buildUsernameContains usernameContains=username_contains/>  
			</#if>
		) 
		AND
			(	device_ip in  (<@buildIPlist iplist=ip_list/>) 
				OR device_host in (<@buildHostlist hostlist=host_list/>)
			)
		AND 
		device_class = 'Windows Hosts' 
		AND
		reference_id IN ('4625', '529', '530', '531','532','533','534','535','536','537','539')
		AND
		medium=32
	).std:groupwin(device_ip,device_host).win:time_length_batch(${time_window?c} sec, ${count?c}) group by device_ip,device_host having count(*) = ${count?c}; 
	
	
<#macro buildUsernameContains usernameContains>
	<@compress single_line=true>
		<#list usernameContains as v>
			user_dst LIKE '%${v.value}%'
			<#if v_has_next> OR </#if>	
		</#list>
	</@compress>
</#macro>


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