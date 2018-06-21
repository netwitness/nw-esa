/*
Version: 2
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')
@Description('${module_desc}')


@Name('IDSData')
create window IncomingConnIPSECAT.win:time(${time_window?c} sec) 
(ip_src String, ip_dst string,  time Long, device_class string,  device_type string);

@Name('IDSEVENTS') 
Insert into IncomingConnIPSECAT
select  *  from Event(device_class in  ('IDS','IPS', 'Intrusion', 'Vulnerability') and ip_dst is not null
);

@Name('RSAECATEVENTS') 
Insert into IncomingConnIPSECAT
select  ip_src as ip_dst, ip_dst as ip_src,  time, device_class, device_type  from Event( device_type='rsaecat' and ip_src is not null
);

@RSAAlert(oneInSeconds=${module_suppress?c})
select a from IncomingConnIPSECAT
  match_recognize (
    partition by ip_dst
    measures A as a, B as b
    pattern ((A+ B)|(B+ A))
    define 
  A as A.device_type != 'rsaecat' ,
  B as B.device_type = 'rsaecat'
  );
