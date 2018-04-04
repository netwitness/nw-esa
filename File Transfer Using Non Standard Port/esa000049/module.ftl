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
		AND
		tcp_dstport IS NOT NULL
		AND
		extension IS NOT NULL
		AND
		tcp_dstport NOT IN (<@buildArray variablelist=variablelist_dst_port/>)
		AND
		extension IN (<@buildArray variablelist=variablelist_extension/>)
	);


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
	<#elseif value.type?starts_with("short") || value.type?starts_with("integer") 
		|| value.type?starts_with("long") || value.type?starts_with("float") || value.type?starts_with("int")>
		${value.value?c}	
	</#if>
</#macro>