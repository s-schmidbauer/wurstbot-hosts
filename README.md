# wurstbot-hosts

## setup managed hosts
add ssh pub key to /root/.ssh/authorized_key
doas pkg_add python-2.7.14

## configure a host
ansible-playbook -m setup -i inventory node1
ansible-playbook -i inventory playbook.yml --ask-pass
