/*
Version: 3
*/

module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"ip_src, ip_dst"})

SELECT * FROM 

	Event(
		medium = 32
		AND
		ip_src IS NOT NULL
		AND
		ip_src NOT IN (<@buildArray variablelist=whitelist_ip_src/>)
		AND
		ip_dst IS NOT NULL
		AND
		ip_dst NOT IN (<@buildArray variablelist=whitelist_ip_dst/>)
		AND		
		msg_id IN (<@buildArray variablelist=msg_id_list/>)
	).std:groupwin(ip_src, ip_dst).win:time_length_batch(${time_window?c} seconds, ${logevent_count?c}).std:unique(msg_id) GROUP BY ip_src, ip_dst HAVING COUNT(*) = ${logevent_count?c};

	
<#macro buildArray variablelist>
	<@compress single_line=true>
	<#list variablelist as v>
		<@buildScalar value=v/>
		<#if v_has_next>,</#if>	
	</#list>
	</@compress>
</#macro>

<#macro buildScalar value>
	<#if value.type?starts_with("string")>
		'${value.value}'
	<#elseif value.type?starts_with("short") || value.type?starts_with("int") || value.type?starts_with("long") || value.type?starts_with("float")>
		${value.value?c}	
	</#if>
</#macro>