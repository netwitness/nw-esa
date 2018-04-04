/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c})

SELECT * FROM
	Event(
		medium = 32
		AND
		device_class = 'Windows Hosts' 
		AND
		ec_activity = 'Logon' 
		AND 
		ec_outcome = 'Success'
		
		<#if username_contains?size &gt; 0>
		AND 
		(
			<@buildMetaContains metaContains=username_contains metakey="user_dst"/>  
		) 
		</#if>
		
		AND 
		logon_type IN ('2','10','11','12') 
		AND 
		reference_id IN ('4624', '528', '540')
	); 
	
	
<#macro buildMetaContains metaContains metakey>
	<@compress single_line=true>
		<#list metaContains as v>
			${metakey} LIKE '%${v.value}%'
			<#if v_has_next> OR </#if>	
		</#list>
	</@compress>
</#macro>