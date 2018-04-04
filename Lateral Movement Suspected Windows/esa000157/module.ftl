/*
Version: 2
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"event_computer"})

select * from
pattern @SuppressOverlappingMatches
[
	every a= Event(medium=32 AND device_class='Windows Hosts' AND reference_id='5145' AND filename IS NOT NULL AND filename.toLowerCase() LIKE '%.exe' AND event_computer IS NOT NULL) 
	->
	(
		b= Event(medium=32 AND device_class='Windows Hosts' AND reference_id='7045' AND filename=a.filename AND event_computer=a.event_computer) 
		-> c= Event(medium=32 AND device_class='Windows Hosts' AND reference_id='7036' AND disposition='running' AND service_name=b.service_name AND event_computer=b.event_computer)
	)
	where timer:within(${time_window?c} seconds)
];