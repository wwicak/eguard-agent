Name: eguard-agent
Version: 0.1.0
Release: 1
Summary: eGuard endpoint agent scaffold
License: GPLv2+
BuildArch: x86_64

%description
eGuard endpoint agent scaffold package.

%package rules
Summary: Optional initial rule bundle for eGuard endpoint agent
Requires: eguard-agent = %{version}-%{release}

%description rules
Optional initial SIGMA/YARA/IOC bundle package for eGuard endpoint agent.

%files
/usr/bin/eguard-agent
/usr/lib/systemd/system/eguard-agent.service
/etc/eguard-agent/agent.conf

%files rules
/var/lib/eguard-agent/rules/sigma
/var/lib/eguard-agent/rules/yara
/var/lib/eguard-agent/rules/ioc
