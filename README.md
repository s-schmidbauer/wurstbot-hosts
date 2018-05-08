# wurstbot-hosts

## setup host
- create new vm
- configure root password
- create dns for node, related dns names (nagios, zabbix, ..)

## setup managed hosts
- add ssh pub key to /root/.ssh/authorized_key
- doas pkg_add python-2.7.14

## configure a host
- export ANSIBLE_NOCOWS=1
- update inventory with host
- ansible-playbook -m setup -i inventory node1
- ansible-playbook -i inventory playbook.yml --ask-pass

## dependencies
http(s) depends on acme
acme depends on http and dns setup for node, related dns names (nagios, zabbix, ..)
