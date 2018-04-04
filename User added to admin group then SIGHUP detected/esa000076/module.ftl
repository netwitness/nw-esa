/*
Version: 2
*/

module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')
@Description('${module_desc}')
@RSAAlert(oneInSeconds=${module_suppress?c})

SELECT * FROM 
			Event(
					(
						(
							ec_subject='Group' AND ec_activity='Modify' AND ec_outcome='Success' AND user_dst is not null AND device_ip IS NOT NULL							
							AND 							
								( 
									<#if group_equals?size &gt; 0>
										`group` IN (<@buildGroupEquals groupEquals=group_equals/>)
									</#if>
								)
						) 
					or 
						(event_desc LIKE '%SIGHUP%' AND device_ip IS NOT NULL) 
					)
					
				).win:time(${time_window?c} sec)
				
	match_recognize (
	partition by device_ip
	measures F as f, S as s
	pattern (F+ S)
	define
	F as F.ec_subject='Group' AND F.ec_activity='Modify' AND F.ec_outcome='Success' ,
	S as S.event_desc LIKE '%SIGHUP%'
	);

	<#macro buildGroupEquals groupEquals>
		<@compress single_line=true>
			<#list groupEquals as u>
				'${u.value}'
				<#if u_has_next>,</#if>	
			</#list>
		</@compress>
	</#macro>