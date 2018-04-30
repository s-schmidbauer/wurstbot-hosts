# wurstbot-hosts

## setup managed hosts
- add ssh pub key to /root/.ssh/authorized_key
- doas pkg_add python-2.7.14

## configure a host
- export ANSIBLE_NOCOWS=1
- ansible-playbook -m setup -i inventory node1
- ansible-playbook -i inventory playbook.yml --ask-pass
