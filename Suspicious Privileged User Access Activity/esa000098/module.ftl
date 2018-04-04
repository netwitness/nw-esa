/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst"})

SELECT * FROM  
			Event(
				medium = 32
			AND
				ec_activity='Logon' 
			AND 
				ec_outcome='Success'
			AND 
				ip_src IS NOT NULL 
			AND 
			(	
				<#if username_contains?size &gt; 0>
				<@buildMetaContains metaContains=username_contains metakey="user_dst"/>  
				</#if>
			)
			).std:groupwin(user_dst)
			.win:time_length_batch(${time_window?c} seconds, ${count?c})
			.std:unique(ip_src) 
			group by user_dst 
			having count(*) = ${count?c};

@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst"})
		
SELECT * FROM  
			Event(
				medium = 32
			AND
				ec_activity='Logon' 
			AND 
				ec_outcome='Success'
			AND 
				host_src IS NOT NULL 
			AND 
			(	
				<#if username_contains?size &gt; 0>
				<@buildMetaContains metaContains=username_contains metakey="user_dst"/>  
				</#if>
			)
			).std:groupwin(user_dst)
			.win:time_length_batch(${time_window?c} seconds, ${count?c})
			.std:unique(host_src) 
			group by user_dst
			having count(*) = ${count?c};


<#macro buildMetaContains metaContains metakey>
	<@compress single_line=true>
		<#list metaContains as v>
			${metakey} LIKE '%${v.value}%'
			<#if v_has_next> OR </#if>	
		</#list>
	</@compress>
</#macro>