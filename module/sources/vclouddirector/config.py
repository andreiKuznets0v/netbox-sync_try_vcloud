# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2023 Ricardo Bartels. All rights reserved.
#
#  netbox-sync.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

#  Modifed by Andrei Kuznetsov 2024

import os
import re

from module.config import source_config_section_name
from module.config.base import ConfigBase
from module.config.option import ConfigOption
from module.config.group import ConfigOptionGroup
from module.sources.common.config import *
from module.common.logging import get_logger
from module.common.misc import quoted_split
from module.sources.common.permitted_subnets import PermittedSubnets

log = get_logger()


class VcloudDirectorConfig(ConfigBase):

    section_name = source_config_section_name
    source_name = None
    source_name_example = "my-clouddirector-example"

    def __init__(self):
        self.options = [
            ConfigOption(**config_option_enabled_definition),

            ConfigOption(**{**config_option_type_definition, "config_example": "check_vclouddirector"}),

            ConfigOption("vcloud_url",
                         str,
                         description="host name / IP address of tenant vdc frontend",
                         config_example="vcloud.example.com",
                         mandatory=True),

            ConfigOption("port",
                         int,
                         description="TCP port to connect to",
                         default_value=443),

            ConfigOption("username",
                         str,
                         description="username to use to log into vCloudDirector",
                         config_example="vCloudDirector-readonly",
                         mandatory=True),

            ConfigOption("password",
                         str,
                         description="password to use to log into vCloudDirector",
                         config_example="super-secret",
                         sensitive=True,
                         mandatory=True),

            ConfigOption("validate_tls_certs",
                         bool,
                         description="""Enforces TLS certificate validation.
                         If vCloudDirector uses a valid TLS certificate then this option should be set
                         to 'true' to ensure a secure connection.""",
                         default_value=False),

            ConfigOption("proxy_host",
                         str,
                         description="""EXPERIMENTAL: Connect to a vCloudDirector using a proxy server
                         (socks proxies are not supported). define a host name or an IP address""",
                         config_example="10.10.1.10"),

            ConfigOption("proxy_port",
                         int,
                         description="""EXPERIMENTAL: Connect to a vCloudDirector using a proxy server
                         (socks proxies are not supported).
                         define proxy server port number""",
                         config_example=3128),

            ConfigOption(**config_option_permitted_subnets_definition),
            
             ConfigOptionGroup(title="filter",
                              description="""filters can be used to include/exclude certain objects from importing
                              into NetBox. Include filters are checked first and exclude filters after.
                              An object name has to pass both filters to be synced to NetBox.
                              If a filter is unset it will be ignored. Filters are all treated as regex expressions!
                              If more then one expression should match, a '|' needs to be used
                              """,
                              config_example="""Example: (exclude all VMs with "replica" in their name 
                              and all VMs starting with "backup"): vm_exclude_filter = .*replica.*|^backup.*""",
                              options=[
                                ConfigOption("cluster_exclude_filter",
                                             str,
                                             description="""If a cluster is excluded from sync then ALL VMs and HOSTS
                                             inside the cluster will be ignored! a cluster can be specified
                                             as "Cluster-name" or "Datacenter-name/Cluster-name" if
                                             multiple clusters have the same name"""),
                                ConfigOption("cluster_include_filter", str),
     
                                ConfigOption("vm_exclude_filter",
                                             str, description="simply include/exclude VMs"),
                                ConfigOption("vm_include_filter", str)
                              ]),
            ConfigOptionGroup(title="relations",
                              options=[
                                ConfigOption("cluster_site_relation",
                                             str,
                                             description="""\
                                             This option defines which vCenter cluster is part of a NetBox site.
                                             This is done with a comma separated key = value list.
                                               key: defines the cluster name as regex
                                               value: defines the NetBox site name (use quotes if name contains commas)
                                             This is a quite important config setting as IP addresses, prefixes, VLANs
                                             and VRFs are site dependent. In order to assign the correct prefix to an IP
                                             address it is important to pick the correct site.
                                             A VM always depends on the cluster site relation
                                             a cluster can be specified as "Cluster-name" or
                                             "Datacenter-name/Cluster-name" if multiple clusters have the same name.
                                             When a vCenter cluster consists of hosts from multiple NetBox sites,
                                             it is possible to leave the site for a NetBox cluster empty. All VMs from
                                             this cluster will then also have no site reference.
                                             The keyword "<NONE>" can be used as a value for this.
                                             """,
                                             config_example="Cluster_NYC = New York, Cluster_FFM.* = Frankfurt, Datacenter_TOKIO/.* = Tokio, Cluster_MultiSite = <NONE>"),
 
                                ConfigOption("cluster_tenant_relation",
                                             str,
                                             description="""\
                                             This option defines which cluster/host/VM belongs to which tenant.
                                             This is done with a comma separated key = value list.
                                               key: defines a hosts/VM name as regex
                                               value: defines the NetBox tenant name (use quotes if name contains commas)
                                             a cluster can be specified as "Cluster-name" or
                                             "Datacenter-name/Cluster-name" if multiple clusters have the same name
                                             """,
                                             config_example="Cluster_NYC.* = Customer A"),
                            
                                ConfigOption("vm_tenant_relation", str, config_example="grafana.* = Infrastructure"),
                                ConfigOption("vm_platform_relation",
                                             str,
                                             description="""\
                                             This option defines custom platforms if the VMWare created platforms are not suitable.
                                             Pretty much a mapping of VMWare platform name to your own platform name.
                                             This is done with a comma separated key = value list.
                                               key: defines a VMWare returned platform name
                                               value: defines the desired NetBox platform name""",
                                             config_example="centos-7.* = centos7, microsoft-windows-server-2016.* = Windows2016"),

                                ConfigOption("vm_role_relation",
                                             str,
                                             description="""\
                                             Define the NetBox device role used for VMs. This is done with a
                                             comma separated key = value list, same as 'host_role_relation'.
                                               key: defines VM(s) name as regex
                                               value: defines the NetBox role name (use quotes if name contains commas)
                                             """,
                                             config_example=".* = Server"),

                                ConfigOption("vm_tag_relation", str, config_example="grafana.* = Infrastructure")
                              ]),
            ConfigOption("sync_custom_attributes",
                         bool,
                         description="""sync custom attributes defined for hosts and VMs
                         in vCenter to NetBox as custom fields""",
                         default_value=False),
            ConfigOptionGroup(title="custom object attributes",
                              description="""\
                              add arbitrary host/vm object attributes as custom fields to NetBox.
                              multiple attributes can be defined comma separated.
                              to get a list of available attributes use '-l DEBUG3' as cli param (CAREFUL: output might be long)
                              and here 'https://gist.github.com/bb-Ricardo/538768487bdac4efafabe56e005cb4ef' can be seen how to
                              access these attributes
                              """,
                              options=[               
                                ConfigOption("vm_custom_object_attributes",
                                             str,
                                             config_example="config.uuid")
                              ]),

            ConfigOption("overwrite_vm_interface_name",
                         bool,
                         description="""define if the name of the VM interface discovered overwrites the
                         interface name in NetBox. The interface will only be matched by identical MAC address""",
                         default_value=True),
            ConfigOption("overwrite_device_platform",
                         bool,
                         description="""define if the platform of the device discovered overwrites the device
                         platform in NetBox.""",
                         default_value=True),
            ConfigOption("overwrite_vm_platform",
                         bool,
                         description="""define if the platform of the VM discovered overwrites the VM
                         platform in NetBox.""",
                         default_value=True),

            ConfigOption(**config_option_ip_tenant_inheritance_order_definition),
            ConfigOption("custom_attribute_exclude",
                         str,
                         description="""defines a comma separated list of custom attribute which should be excluded
                         from sync. Any custom attribute with a matching attribute key will be excluded from sync.
                         """,
                         config_example="VB_LAST_BACKUP, VB_LAST_BACKUP2"
                         ),
        ]

        super().__init__()

    def validate_options(self):

        for option in self.options:

            if option.value is None:
                continue

            if "relation" in option.key:

                relation_data = list()

                relation_type = option.key.split("_")[1]

                for relation in quoted_split(option.value):

                    object_name = relation.split("=")[0].strip(' "')
                    relation_name = relation.split("=")[1].strip(' "')

                    if len(object_name) == 0 or len(relation_name) == 0:
                        log.error(f"Config option '{relation}' malformed got '{object_name}' for "
                                  f"object name and '{relation_name}' for {relation_type} name.")
                        self.set_validation_failed()
                        continue

                    try:
                        re_compiled = re.compile(object_name)
                    except Exception as e:
                        log.error(f"Problem parsing regular expression '{object_name}' for '{relation}': {e}")
                        self.set_validation_failed()
                        continue

                    relation_data.append({
                        "object_regex": re_compiled,
                        "assigned_name": relation_name
                    })

                option.set_value(relation_data)

                continue
             
        permitted_subnets_option = self.get_option_by_name("permitted_subnets")

        if permitted_subnets_option is not None:
            permitted_subnets = PermittedSubnets(permitted_subnets_option.value)
            if permitted_subnets.validation_failed is True:
                self.set_validation_failed()

            permitted_subnets_option.set_value(permitted_subnets)
