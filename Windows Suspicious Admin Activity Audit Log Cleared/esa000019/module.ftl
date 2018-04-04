/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_src"})

select * from pattern @SuppressOverlappingMatches [

every a=Event (reference_id IN ('624', '4720') AND device_class = 'Windows Hosts' AND medium=32 AND event_source.toLowerCase() IN ('security','microsoft-windows-security-auditing') AND user_src IS NOT NULL)
-> (b=Event(user_src = a.user_src AND reference_id IN ('632','4728','636','4732','4751','660','4756','655','4761') AND device_class = 'Windows Hosts' AND medium=32  AND event_source.toLowerCase() IN ('security','microsoft-windows-security-auditing'))
->  c=Event(((reference_id='517' AND user_src = a.user_src) OR (reference_id='1102' AND user_dst = a.user_src)) AND device_class = 'Windows Hosts' AND event_source.toLowerCase() IN ('security','microsoft-windows-eventlog') AND medium=32 AND (device_ip is not null or device_host is not null)))

where timer:within(${time_window?c} seconds)
];