
# Systemd Service

## Description

### MITRE Description

> Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence. The systemd service manager is commonly used for managing background daemon processes (also known as services) and other system resources.(Citation: Linux man-pages: systemd January 2014)(Citation: Freedesktop.org Linux systemd 29SEP2018) Systemd is the default initialization (init) system on many Linux distributions starting with Debian 8, Ubuntu 15.04, CentOS 7, RHEL 7, Fedora 15, and replaces legacy init systems including SysVinit and Upstart while remaining backwards compatible with the aforementioned init systems.

Systemd utilizes configuration files known as service units to control how services boot and under what conditions. By default, these unit files are stored in the <code>/etc/systemd/system</code> and <code>/usr/lib/systemd/system</code> directories and have the file extension <code>.service</code>. Each service unit file may contain numerous directives that can execute system commands:

* ExecStart, ExecStartPre, and ExecStartPost directives cover execution of commands when a services is started manually by 'systemctl' or on system start if the service is set to automatically start. 
* ExecReload directive covers when a service restarts. 
* ExecStop and ExecStopPost directives cover when a service is stopped or manually by 'systemctl'.

Adversaries have used systemd functionality to establish persistent access to victim systems by creating and/or modifying service unit files that cause systemd to execute malicious commands at recurring intervals, such as at system boot.(Citation: Anomali Rocke March 2019)(Citation: gist Arch package compromise 10JUL2018)(Citation: Arch Linux Package Systemd Compromise BleepingComputer 10JUL2018)(Citation: acroread package compromised Arch Linux Mail 8JUL2018)

While adversaries typically require root privileges to create/modify service unit files in the <code>/etc/systemd/system</code> and <code>/usr/lib/systemd/system</code> directories, low privilege users can create/modify service unit files in directories such as <code>~/.config/systemd/user/</code> to achieve user-level persistence.(Citation: Rapid7 Service Persistence 22JUNE2016)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'root']
* Platforms: ['Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1543/002

## Potential Commands

```
echo "[Unit]" > #{systemd_service_path}/art-systemd-service.service
echo "Description=Atomic Red Team Systemd Service" >> #{systemd_service_path}/art-systemd-service.service
echo "" >> #{systemd_service_path}/art-systemd-service.service
echo "[Service]" >> #{systemd_service_path}/art-systemd-service.service
echo "Type=simple"
echo "ExecStart=#{execstart_action}" >> #{systemd_service_path}/art-systemd-service.service
echo "ExecStartPre=#{execstartpre_action}" >> #{systemd_service_path}/art-systemd-service.service
echo "ExecStartPost=#{execstartpost_action}" >> #{systemd_service_path}/art-systemd-service.service
echo "ExecReload=#{execreload_action}" >> #{systemd_service_path}/art-systemd-service.service
echo "ExecStop=#{execstop_action}" >> #{systemd_service_path}/art-systemd-service.service
echo "ExecStopPost=#{execstoppost_action}" >> #{systemd_service_path}/art-systemd-service.service
echo "" >> #{systemd_service_path}/art-systemd-service.service
echo "[Install]" >> #{systemd_service_path}/art-systemd-service.service
echo "WantedBy=default.target" >> #{systemd_service_path}/art-systemd-service.service
systemctl daemon-reload
systemctl enable art-systemd-service.service
systemctl start art-systemd-service.service
echo "[Unit]" > /etc/systemd/system/#{systemd_service_file}
echo "Description=Atomic Red Team Systemd Service" >> /etc/systemd/system/#{systemd_service_file}
echo "" >> /etc/systemd/system/#{systemd_service_file}
echo "[Service]" >> /etc/systemd/system/#{systemd_service_file}
echo "Type=simple"
echo "ExecStart=#{execstart_action}" >> /etc/systemd/system/#{systemd_service_file}
echo "ExecStartPre=#{execstartpre_action}" >> /etc/systemd/system/#{systemd_service_file}
echo "ExecStartPost=#{execstartpost_action}" >> /etc/systemd/system/#{systemd_service_file}
echo "ExecReload=#{execreload_action}" >> /etc/systemd/system/#{systemd_service_file}
echo "ExecStop=#{execstop_action}" >> /etc/systemd/system/#{systemd_service_file}
echo "ExecStopPost=#{execstoppost_action}" >> /etc/systemd/system/#{systemd_service_file}
echo "" >> /etc/systemd/system/#{systemd_service_file}
echo "[Install]" >> /etc/systemd/system/#{systemd_service_file}
echo "WantedBy=default.target" >> /etc/systemd/system/#{systemd_service_file}
systemctl daemon-reload
systemctl enable #{systemd_service_file}
systemctl start #{systemd_service_file}
echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}
echo "Description=Atomic Red Team Systemd Service" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Service]" >> #{systemd_service_path}/#{systemd_service_file}
echo "Type=simple"
echo "ExecStart=/bin/touch /tmp/art-systemd-execstart-marker" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPre=#{execstartpre_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPost=#{execstartpost_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecReload=#{execreload_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStop=#{execstop_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStopPost=#{execstoppost_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Install]" >> #{systemd_service_path}/#{systemd_service_file}
echo "WantedBy=default.target" >> #{systemd_service_path}/#{systemd_service_file}
systemctl daemon-reload
systemctl enable #{systemd_service_file}
systemctl start #{systemd_service_file}
echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}
echo "Description=Atomic Red Team Systemd Service" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Service]" >> #{systemd_service_path}/#{systemd_service_file}
echo "Type=simple"
echo "ExecStart=#{execstart_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPre=#{execstartpre_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPost=#{execstartpost_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecReload=/bin/touch /tmp/art-systemd-execreload-marker" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStop=#{execstop_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStopPost=#{execstoppost_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Install]" >> #{systemd_service_path}/#{systemd_service_file}
echo "WantedBy=default.target" >> #{systemd_service_path}/#{systemd_service_file}
systemctl daemon-reload
systemctl enable #{systemd_service_file}
systemctl start #{systemd_service_file}
echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}
echo "Description=Atomic Red Team Systemd Service" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Service]" >> #{systemd_service_path}/#{systemd_service_file}
echo "Type=simple"
echo "ExecStart=#{execstart_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPre=#{execstartpre_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPost=/bin/touch /tmp/art-systemd-execstartpost-marker" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecReload=#{execreload_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStop=#{execstop_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStopPost=#{execstoppost_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Install]" >> #{systemd_service_path}/#{systemd_service_file}
echo "WantedBy=default.target" >> #{systemd_service_path}/#{systemd_service_file}
systemctl daemon-reload
systemctl enable #{systemd_service_file}
systemctl start #{systemd_service_file}
echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}
echo "Description=Atomic Red Team Systemd Service" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Service]" >> #{systemd_service_path}/#{systemd_service_file}
echo "Type=simple"
echo "ExecStart=#{execstart_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPre=/bin/touch /tmp/art-systemd-execstartpre-marker" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPost=#{execstartpost_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecReload=#{execreload_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStop=#{execstop_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStopPost=#{execstoppost_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Install]" >> #{systemd_service_path}/#{systemd_service_file}
echo "WantedBy=default.target" >> #{systemd_service_path}/#{systemd_service_file}
systemctl daemon-reload
systemctl enable #{systemd_service_file}
systemctl start #{systemd_service_file}
echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}
echo "Description=Atomic Red Team Systemd Service" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Service]" >> #{systemd_service_path}/#{systemd_service_file}
echo "Type=simple"
echo "ExecStart=#{execstart_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPre=#{execstartpre_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPost=#{execstartpost_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecReload=#{execreload_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStop=#{execstop_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStopPost=/bin/touch /tmp/art-systemd-execstoppost-marker" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Install]" >> #{systemd_service_path}/#{systemd_service_file}
echo "WantedBy=default.target" >> #{systemd_service_path}/#{systemd_service_file}
systemctl daemon-reload
systemctl enable #{systemd_service_file}
systemctl start #{systemd_service_file}
echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}
echo "Description=Atomic Red Team Systemd Service" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Service]" >> #{systemd_service_path}/#{systemd_service_file}
echo "Type=simple"
echo "ExecStart=#{execstart_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPre=#{execstartpre_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPost=#{execstartpost_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecReload=#{execreload_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStop=/bin/touch /tmp/art-systemd-execstop-marker" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStopPost=#{execstoppost_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Install]" >> #{systemd_service_path}/#{systemd_service_file}
echo "WantedBy=default.target" >> #{systemd_service_path}/#{systemd_service_file}
systemctl daemon-reload
systemctl enable #{systemd_service_file}
systemctl start #{systemd_service_file}
```

## Commands Dataset

```
[{'command': 'echo "[Unit]" > /etc/systemd/system/#{systemd_service_file}\n'
             'echo "Description=Atomic Red Team Systemd Service" >> '
             '/etc/systemd/system/#{systemd_service_file}\n'
             'echo "" >> /etc/systemd/system/#{systemd_service_file}\n'
             'echo "[Service]" >> /etc/systemd/system/#{systemd_service_file}\n'
             'echo "Type=simple"\n'
             'echo "ExecStart=#{execstart_action}" >> '
             '/etc/systemd/system/#{systemd_service_file}\n'
             'echo "ExecStartPre=#{execstartpre_action}" >> '
             '/etc/systemd/system/#{systemd_service_file}\n'
             'echo "ExecStartPost=#{execstartpost_action}" >> '
             '/etc/systemd/system/#{systemd_service_file}\n'
             'echo "ExecReload=#{execreload_action}" >> '
             '/etc/systemd/system/#{systemd_service_file}\n'
             'echo "ExecStop=#{execstop_action}" >> '
             '/etc/systemd/system/#{systemd_service_file}\n'
             'echo "ExecStopPost=#{execstoppost_action}" >> '
             '/etc/systemd/system/#{systemd_service_file}\n'
             'echo "" >> /etc/systemd/system/#{systemd_service_file}\n'
             'echo "[Install]" >> /etc/systemd/system/#{systemd_service_file}\n'
             'echo "WantedBy=default.target" >> '
             '/etc/systemd/system/#{systemd_service_file}\n'
             'systemctl daemon-reload\n'
             'systemctl enable #{systemd_service_file}\n'
             'systemctl start #{systemd_service_file}\n',
  'name': None,
  'source': 'atomics/T1543.002/T1543.002.yaml'},
 {'command': 'echo "[Unit]" > '
             '#{systemd_service_path}/art-systemd-service.service\n'
             'echo "Description=Atomic Red Team Systemd Service" >> '
             '#{systemd_service_path}/art-systemd-service.service\n'
             'echo "" >> #{systemd_service_path}/art-systemd-service.service\n'
             'echo "[Service]" >> '
             '#{systemd_service_path}/art-systemd-service.service\n'
             'echo "Type=simple"\n'
             'echo "ExecStart=#{execstart_action}" >> '
             '#{systemd_service_path}/art-systemd-service.service\n'
             'echo "ExecStartPre=#{execstartpre_action}" >> '
             '#{systemd_service_path}/art-systemd-service.service\n'
             'echo "ExecStartPost=#{execstartpost_action}" >> '
             '#{systemd_service_path}/art-systemd-service.service\n'
             'echo "ExecReload=#{execreload_action}" >> '
             '#{systemd_service_path}/art-systemd-service.service\n'
             'echo "ExecStop=#{execstop_action}" >> '
             '#{systemd_service_path}/art-systemd-service.service\n'
             'echo "ExecStopPost=#{execstoppost_action}" >> '
             '#{systemd_service_path}/art-systemd-service.service\n'
             'echo "" >> #{systemd_service_path}/art-systemd-service.service\n'
             'echo "[Install]" >> '
             '#{systemd_service_path}/art-systemd-service.service\n'
             'echo "WantedBy=default.target" >> '
             '#{systemd_service_path}/art-systemd-service.service\n'
             'systemctl daemon-reload\n'
             'systemctl enable art-systemd-service.service\n'
             'systemctl start art-systemd-service.service\n',
  'name': None,
  'source': 'atomics/T1543.002/T1543.002.yaml'},
 {'command': 'echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "Description=Atomic Red Team Systemd Service" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "" >> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "[Service]" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "Type=simple"\n'
             'echo "ExecStart=#{execstart_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStartPre=#{execstartpre_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStartPost=#{execstartpost_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecReload=#{execreload_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStop=#{execstop_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStopPost=/bin/touch '
             '/tmp/art-systemd-execstoppost-marker" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "" >> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "[Install]" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "WantedBy=default.target" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'systemctl daemon-reload\n'
             'systemctl enable #{systemd_service_file}\n'
             'systemctl start #{systemd_service_file}\n',
  'name': None,
  'source': 'atomics/T1543.002/T1543.002.yaml'},
 {'command': 'echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "Description=Atomic Red Team Systemd Service" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "" >> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "[Service]" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "Type=simple"\n'
             'echo "ExecStart=#{execstart_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStartPre=#{execstartpre_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStartPost=#{execstartpost_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecReload=/bin/touch /tmp/art-systemd-execreload-marker" '
             '>> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStop=#{execstop_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStopPost=#{execstoppost_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "" >> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "[Install]" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "WantedBy=default.target" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'systemctl daemon-reload\n'
             'systemctl enable #{systemd_service_file}\n'
             'systemctl start #{systemd_service_file}\n',
  'name': None,
  'source': 'atomics/T1543.002/T1543.002.yaml'},
 {'command': 'echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "Description=Atomic Red Team Systemd Service" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "" >> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "[Service]" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "Type=simple"\n'
             'echo "ExecStart=/bin/touch /tmp/art-systemd-execstart-marker" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStartPre=#{execstartpre_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStartPost=#{execstartpost_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecReload=#{execreload_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStop=#{execstop_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStopPost=#{execstoppost_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "" >> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "[Install]" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "WantedBy=default.target" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'systemctl daemon-reload\n'
             'systemctl enable #{systemd_service_file}\n'
             'systemctl start #{systemd_service_file}\n',
  'name': None,
  'source': 'atomics/T1543.002/T1543.002.yaml'},
 {'command': 'echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "Description=Atomic Red Team Systemd Service" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "" >> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "[Service]" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "Type=simple"\n'
             'echo "ExecStart=#{execstart_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStartPre=#{execstartpre_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStartPost=#{execstartpost_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecReload=#{execreload_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStop=/bin/touch /tmp/art-systemd-execstop-marker" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStopPost=#{execstoppost_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "" >> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "[Install]" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "WantedBy=default.target" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'systemctl daemon-reload\n'
             'systemctl enable #{systemd_service_file}\n'
             'systemctl start #{systemd_service_file}\n',
  'name': None,
  'source': 'atomics/T1543.002/T1543.002.yaml'},
 {'command': 'echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "Description=Atomic Red Team Systemd Service" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "" >> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "[Service]" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "Type=simple"\n'
             'echo "ExecStart=#{execstart_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStartPre=/bin/touch '
             '/tmp/art-systemd-execstartpre-marker" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStartPost=#{execstartpost_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecReload=#{execreload_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStop=#{execstop_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStopPost=#{execstoppost_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "" >> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "[Install]" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "WantedBy=default.target" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'systemctl daemon-reload\n'
             'systemctl enable #{systemd_service_file}\n'
             'systemctl start #{systemd_service_file}\n',
  'name': None,
  'source': 'atomics/T1543.002/T1543.002.yaml'},
 {'command': 'echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "Description=Atomic Red Team Systemd Service" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "" >> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "[Service]" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "Type=simple"\n'
             'echo "ExecStart=#{execstart_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStartPre=#{execstartpre_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStartPost=/bin/touch '
             '/tmp/art-systemd-execstartpost-marker" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecReload=#{execreload_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStop=#{execstop_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "ExecStopPost=#{execstoppost_action}" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "" >> #{systemd_service_path}/#{systemd_service_file}\n'
             'echo "[Install]" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'echo "WantedBy=default.target" >> '
             '#{systemd_service_path}/#{systemd_service_file}\n'
             'systemctl daemon-reload\n'
             'systemctl enable #{systemd_service_file}\n'
             'systemctl start #{systemd_service_file}\n',
  'name': None,
  'source': 'atomics/T1543.002/T1543.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Create or Modify System Process: Systemd Service': {'atomic_tests': [{'auto_generated_guid': 'd9e4f24f-aa67-4c6e-bcbf-85622b697a7c',
                                                                                                'description': 'This '
                                                                                                               'test '
                                                                                                               'creates '
                                                                                                               'a '
                                                                                                               'Systemd '
                                                                                                               'service '
                                                                                                               'unit '
                                                                                                               'file '
                                                                                                               'and '
                                                                                                               'enables '
                                                                                                               'it '
                                                                                                               'as '
                                                                                                               'a '
                                                                                                               'service.\n',
                                                                                                'executor': {'cleanup_command': 'systemctl '
                                                                                                                                'stop '
                                                                                                                                '#{systemd_service_file}\n'
                                                                                                                                'systemctl '
                                                                                                                                'disable '
                                                                                                                                '#{systemd_service_file}\n'
                                                                                                                                'rm '
                                                                                                                                '-rf '
                                                                                                                                '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                                'systemctl '
                                                                                                                                'daemon-reload\n',
                                                                                                             'command': 'echo '
                                                                                                                        '"[Unit]" '
                                                                                                                        '> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'echo '
                                                                                                                        '"Description=Atomic '
                                                                                                                        'Red '
                                                                                                                        'Team '
                                                                                                                        'Systemd '
                                                                                                                        'Service" '
                                                                                                                        '>> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'echo '
                                                                                                                        '"" '
                                                                                                                        '>> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'echo '
                                                                                                                        '"[Service]" '
                                                                                                                        '>> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'echo '
                                                                                                                        '"Type=simple"\n'
                                                                                                                        'echo '
                                                                                                                        '"ExecStart=#{execstart_action}" '
                                                                                                                        '>> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'echo '
                                                                                                                        '"ExecStartPre=#{execstartpre_action}" '
                                                                                                                        '>> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'echo '
                                                                                                                        '"ExecStartPost=#{execstartpost_action}" '
                                                                                                                        '>> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'echo '
                                                                                                                        '"ExecReload=#{execreload_action}" '
                                                                                                                        '>> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'echo '
                                                                                                                        '"ExecStop=#{execstop_action}" '
                                                                                                                        '>> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'echo '
                                                                                                                        '"ExecStopPost=#{execstoppost_action}" '
                                                                                                                        '>> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'echo '
                                                                                                                        '"" '
                                                                                                                        '>> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'echo '
                                                                                                                        '"[Install]" '
                                                                                                                        '>> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'echo '
                                                                                                                        '"WantedBy=default.target" '
                                                                                                                        '>> '
                                                                                                                        '#{systemd_service_path}/#{systemd_service_file}\n'
                                                                                                                        'systemctl '
                                                                                                                        'daemon-reload\n'
                                                                                                                        'systemctl '
                                                                                                                        'enable '
                                                                                                                        '#{systemd_service_file}\n'
                                                                                                                        'systemctl '
                                                                                                                        'start '
                                                                                                                        '#{systemd_service_file}\n',
                                                                                                             'name': 'bash'},
                                                                                                'input_arguments': {'execreload_action': {'default': '/bin/touch '
                                                                                                                                                     '/tmp/art-systemd-execreload-marker',
                                                                                                                                          'description': 'ExecReload '
                                                                                                                                                         'action '
                                                                                                                                                         'for '
                                                                                                                                                         'Systemd '
                                                                                                                                                         'service',
                                                                                                                                          'type': 'String'},
                                                                                                                    'execstart_action': {'default': '/bin/touch '
                                                                                                                                                    '/tmp/art-systemd-execstart-marker',
                                                                                                                                         'description': 'ExecStart '
                                                                                                                                                        'action '
                                                                                                                                                        'for '
                                                                                                                                                        'Systemd '
                                                                                                                                                        'service',
                                                                                                                                         'type': 'String'},
                                                                                                                    'execstartpost_action': {'default': '/bin/touch '
                                                                                                                                                        '/tmp/art-systemd-execstartpost-marker',
                                                                                                                                             'description': 'ExecStartPost '
                                                                                                                                                            'action '
                                                                                                                                                            'for '
                                                                                                                                                            'Systemd '
                                                                                                                                                            'service',
                                                                                                                                             'type': 'String'},
                                                                                                                    'execstartpre_action': {'default': '/bin/touch '
                                                                                                                                                       '/tmp/art-systemd-execstartpre-marker',
                                                                                                                                            'description': 'ExecStartPre '
                                                                                                                                                           'action '
                                                                                                                                                           'for '
                                                                                                                                                           'Systemd '
                                                                                                                                                           'service',
                                                                                                                                            'type': 'String'},
                                                                                                                    'execstop_action': {'default': '/bin/touch '
                                                                                                                                                   '/tmp/art-systemd-execstop-marker',
                                                                                                                                        'description': 'ExecStop '
                                                                                                                                                       'action '
                                                                                                                                                       'for '
                                                                                                                                                       'Systemd '
                                                                                                                                                       'service',
                                                                                                                                        'type': 'String'},
                                                                                                                    'execstoppost_action': {'default': '/bin/touch '
                                                                                                                                                       '/tmp/art-systemd-execstoppost-marker',
                                                                                                                                            'description': 'ExecStopPost '
                                                                                                                                                           'action '
                                                                                                                                                           'for '
                                                                                                                                                           'Systemd '
                                                                                                                                                           'service',
                                                                                                                                            'type': 'String'},
                                                                                                                    'systemd_service_file': {'default': 'art-systemd-service.service',
                                                                                                                                             'description': 'File '
                                                                                                                                                            'name '
                                                                                                                                                            'of '
                                                                                                                                                            'systemd '
                                                                                                                                                            'service '
                                                                                                                                                            'unit '
                                                                                                                                                            'file',
                                                                                                                                             'type': 'String'},
                                                                                                                    'systemd_service_path': {'default': '/etc/systemd/system',
                                                                                                                                             'description': 'Path '
                                                                                                                                                            'to '
                                                                                                                                                            'systemd '
                                                                                                                                                            'service '
                                                                                                                                                            'unit '
                                                                                                                                                            'file',
                                                                                                                                             'type': 'Path'}},
                                                                                                'name': 'Create '
                                                                                                        'Systemd '
                                                                                                        'Service',
                                                                                                'supported_platforms': ['linux']}],
                                                                              'attack_technique': 'T1543.002',
                                                                              'display_name': 'Create '
                                                                                              'or '
                                                                                              'Modify '
                                                                                              'System '
                                                                                              'Process: '
                                                                                              'Systemd '
                                                                                              'Service'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Limit Software Installation](../mitigations/Limit-Software-Installation.md)
    
* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    

# Actors


* [Rocke](../actors/Rocke.md)

