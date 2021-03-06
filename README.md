# vCD inventory plugin

Este repositorio contiene un plugin de inventario de ansible, para obtener el listado de máquinas virtuales existentes en un VDC de vCloud Director.

## Requisitos

Este plugin necesita que se instale la librería [pyvcloud](https://pypi.org/project/pyvcloud/). La versión probada actualmente es la **22.0.1**:

```bash
$ pip install pyvcloud==22.0.1
```

## Uso

El plugin recibe su configuración de un fichero de inventario cuyo nombre **debe tener la (doble) extensión** *.vcd.yaml*. Los pasos para utilizar este inventario son:

- Crear un directorio *inventory_plugins* dentro del directorio donde estén los playbooks.
- Copiar el fichero *vcd.py* en el directorio *inventory_plugins*.
- Crear un fichero de inventario *_nombre_.vcd.yaml* con al menos la siguiente configuración:

```yaml
plugin: vcd

# True to check HTTPS certificate validity
validate_certs: true

# API version 30.0 for vCD 9.1
api_version: "30.0"

# Which NIC is the mgmt NIC (in case the VM has many)
mgmt_nic: 0

# Name of log file to save pyvcloud log
log_file: pyvcloud.log

# True if the inventory should return only powered-on VMs
only_on: false

# Match only vApps starting with this prefix
only_prefix: ""

# True to check DNAT rules at edges for mappings of port SSH 22
check_dnat: true

# True if we must compose host names using vApp name + VM name
# (in case there are different VMs with the same name in different vApps)
compose_names: false

# Number of threads for collecting info from vCD
threads: 16

# True to replace dashes ('-') in group names with underscores ('_')
replace_dash: false

# Metadata property that contains the ansible host group.
# This property contains the sequence of ansible groups to
# which the VMs belong.
#
# consecutive groups are nested, i.e. if the VM's metadata
# is set to "pre3, pre3-iot, pre3-iot-hadoop, pre3-iot-hadoop-ab",
# then the ansible inventory will have this structure:
#
# pre3:
#   pre3-iot:
#     pre3-iot-hadoop:
#       pre3-iot-hadoop-ab:
#         - "instance-name-01"
#         - "instance-name-02"
#         ... etc
ansible_meta: ansible_host_groups

# Metadata property that contains the ansible host vars.
# This property contains a sequence of key=value pairs,
# "key1=value1, key2=value2, ..."
#
# Each key is assigned as a host var to the proper host.
ansible_meta_vars: ansible_host_vars

# Guest property that contains the ansible host groups.
# Just like ansible_meta, but looks for the value in
# guest properties instead of metadata.
# 
# If the group list is found both in metadata and guest
# properties, the guest properties take precedence.
ansible_property: ansible_host_groups

# El módulo soporta cache. Debe configurarse un plugin de caché aparte
# Ver https://docs.ansible.com/ansible/latest/plugins/cache.html
cache: true
```

- Añadir el resto de configuraciones necesarias como variables de entorno:

```bash
export VCLOUD_HOST=nombre.del.servidor
export VCLOUD_USERNAME=usuario
export VCLOUD_PASSWORD=password
export VCLOUD_ORG=nombre.de.org
export VCLOUD_VDC=nombre.de.vdc
```

- Opcionalmente, [habilitar caché](https://docs.ansible.com/ansible/latest/plugins/cache.html). Por ejemplo, exportando las variables de entorno:

```bash
export ANSIBLE_INVENTORY_CACHE=True
export ANSIBLE_INVENTORY_CACHE_PLUGIN=jsonfile
# Directorio donde se almacenará el caché
export ANSIBLE_CACHE_PLUGIN_CONNECTION=cache
```

Tras estos pasos, es posible utilizar el fichero *_nombre_.vcd.yaml* como inventario de ansible:

```bash
ansible-playbook -i <ruta/al/fichero/<nombre>.vcd.yaml> ...
```

## Prueba

Una vez completada la instalación y configuración, se puede probar el inventario ejecutando el siguiente comando desde el directorio de los playbooks (NOTA: reemplazar **_nombre_.vcd.yaml** por el nombre del fichero de configuración del inventario):

```bash
ansible-inventory -i _nombre_.vcd.yaml --playbook-dir ./ --list
```

Si se ha habilitado la caché y queremos que la refresque, será necesario borrar ese fichero de caché antes de ejecutar ansible.

## Composición

En caso de querer añadir a los hosts atributos adicionales, se puede usar el plugin [constructed](https://docs.ansible.com/ansible/latest/plugins/inventory/constructed.html) de Ansible para extender el inventario VCD con nuevos hosts, grupos o atributos. Por ejemplo:

```yaml
# Este inventario añade el atributo ansible_user = 'username' a todos los hosts
# del inventario con el que se componga.
plugin: constructed
compose:
  ansible_user: "'username'"
```

Para obtener el resultado deseado, se deben incluir ambos inventarios (el inventario *VCD* y el *constructed*) al invocar a ansible:

```bash
ansible-playbook -i _nombre_.vcd.yaml -i _nombre_.constructed.yaml ...
```
