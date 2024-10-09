# -*- coding: utf-8 -*-
#  for load data from vmWare vCloud Director t
#  netbox-sync.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.
#  based on Pyvcloud Examples list-vapps.py  and pull request from https://github.com/dupondje/netbox-sync.git

import os
import re
import math
import datetime
import pprint
import ssl
from ipaddress import ip_address, ip_network, ip_interface, IPv4Network
from urllib.parse import unquote
#
import urllib3
import requests
import http
from packaging import version

from module.sources.common.source_base import SourceBase
from module.sources.vclouddirector.config import VcloudDirectorConfig
from module.common.logging import get_logger, DEBUG3
from module.common.misc import grab, dump, get_string_or_none, plural
from module.common.support import normalize_mac_address
from module.netbox.inventory import NetBoxInventory
from module.netbox import *


import xmltodict
from lxml import etree
from lxml import objectify

# Import Modules for Vcloud Director
from pyvcloud.vcd.client import BasicLoginCredentials
from pyvcloud.vcd.client import Client
from pyvcloud.vcd.client import EntityType
from pyvcloud.vcd.org import Org
from pyvcloud.vcd.vdc import VDC
from pyvcloud.vcd.vapp import VApp
from pyvcloud.vcd.vm import VM
from pyvcloud.vcd import utils

log = get_logger()


class CheckCloudDirector(SourceBase):
    """
    Source class to import Vcloud Director inventory files
    """

    dependent_netbox_objects = [
        NBTag,
        NBManufacturer,
        NBDeviceType,
        NBPlatform,
        NBClusterType,
        NBClusterGroup,
        NBDeviceRole,
        NBSite,
        NBCluster,
        NBDevice,
        NBVM,
        NBVMInterface,
        NBInterface,
        NBIPAddress,
        NBPrefix,
        NBTenant,
        NBVRF,
        NBVLAN,
        NBCustomField,
        NBVirtualDisk
    ]

    
    source_type = "vcloud_director"
    #enabled = False

    vcloudClient = None
    device_object = None
    
    site_name = None
    #permitted_subnets = None
    #vcd_org     

    def __init__(self, name=None):
  
        if name is None:
            raise ValueError(f"Invalid value for attribute 'name': '{name}'.")

        self.inventory = NetBoxInventory()
        self.name = name

        # parse settings
        settings_handler = VcloudDirectorConfig()
        settings_handler.source_name = self.name
        self.settings = settings_handler.parse()

        self.set_source_tag()
        self.site_name = f"vCloud: {name}"

        if self.settings.enabled is False:
            log.info(f"Source '{name}' is currently disabled. Skipping")
            return


        self.create_api_session()

        self.init_successful = True

        self.permitted_clusters = dict()

        self.vdc_network_info = dict()


    def parse_config_settings(self, config_settings):
        """
        Validate parsed settings from config file

        Parameters
        ----------
        config_settings: dict
            dict of config settings

        """
        
        validation_failed = False
        for setting in ["vcloud_url", "vcloud_org", "username", "password"]:
            if config_settings.get(setting) is None:
                log.error(f"Config option '{setting}' in 'source/{self.name}' can't be empty/undefined")
                validation_failed = True

        # check permitted ip subnets
        if config_settings.get("permitted_subnets") is None:
            log.info(f"Config option 'permitted_subnets' in 'source/{self.name}' is undefined. "
                     f"No IP addresses will be populated to NetBox!")
        else:
            config_settings["permitted_subnets"] = \
                [x.strip() for x in config_settings.get("permitted_subnets").split(",") if x.strip() != ""]

            permitted_subnets = list()
            for permitted_subnet in config_settings["permitted_subnets"]:
                try:
                    permitted_subnets.append(ip_network(permitted_subnet))
                except Exception as e:
                    log.error(f"Problem parsing permitted subnet: {e}")
                    validation_failed = True

            config_settings["permitted_subnets"] = permitted_subnets

        # check include and exclude filter expressions
        for setting in [x for x in config_settings.keys() if "filter" in x]:
            if config_settings.get(setting) is None or config_settings.get(setting).strip() == "":
                continue

            re_compiled = None
            try:
                re_compiled = re.compile(config_settings.get(setting))
            except Exception as e:
                log.error(f"Problem parsing regular expression for '{setting}': {e}")
                validation_failed = True

            config_settings[setting] = re_compiled

        for relation_option in [x for x in self.settings.keys() if "relation" in x]:

            if config_settings.get(relation_option) is None:
                continue

            relation_data = list()

            relation_type = relation_option.split("_")[1]

            # obey quotations to be able to add names including a comma
            # thanks to: https://stackoverflow.com/a/64333329
            for relation in re.split(r",(?=(?:[^\"']*[\"'][^\"']*[\"'])*[^\"']*$)",
                                     config_settings.get(relation_option)):

                object_name = relation.split("=")[0].strip(' "')
                relation_name = relation.split("=")[1].strip(' "')

                if len(object_name) == 0 or len(relation_name) == 0:
                    log.error(f"Config option '{relation}' malformed got '{object_name}' for "
                              f"object name and '{relation_name}' for {relation_type} name.")
                    validation_failed = True

                try:
                    re_compiled = re.compile(object_name)
                except Exception as e:
                    log.error(f"Problem parsing regular expression '{object_name}' for '{relation}': {e}")
                    validation_failed = True
                    continue

                relation_data.append({
                    "object_regex": re_compiled,
                    "assigned_name": relation_name
                })

            config_settings[relation_option] = relation_data

        if config_settings.get("dns_name_lookup") is True and config_settings.get("custom_dns_servers") is not None:

            custom_dns_servers = \
                [x.strip() for x in config_settings.get("custom_dns_servers").split(",") if x.strip() != ""]

            tested_custom_dns_servers = list()
            for custom_dns_server in custom_dns_servers:
                try:
                    tested_custom_dns_servers.append(str(ip_address(custom_dns_server)))
                except ValueError:
                    log.error(f"Config option 'custom_dns_servers' value '{custom_dns_server}' "
                              f"does not appear to be an IP address.")
                    validation_failed = True

            config_settings["custom_dns_servers"] = tested_custom_dns_servers

        if validation_failed is True:
            log.error("Config validation failed. Exit!")
            exit(1)

        for setting in self.settings.keys():
            setattr(self, setting, config_settings.get(setting))

        


    def apply(self):
        """
        Main source handler method. This method is called for each source from "main" program
        to retrieve data from it source and apply it to the NetBox inventory.

        Every update of new/existing objects fot this source has to happen here.

        First try to find and iterate over each inventory file.
        Then parse the system data first and then all components.
        """
        # add tags
        self.add_necessary_base_objects()
        
        vdc_org = self.get_vcloud_org(self.vcloudClient)
        self.add_datacenter( {"name": vdc_org.get_name() } )

        vdc_list = self.get_vdc_list(vdc_org)

        for vdc in vdc_list:
            
            log.info(f"Add virtual cluster for '{vdc_org.get_name()}")
            self.add_cluster(vdc,vdc_org.get_name())
            vdc_resource = vdc_org.get_vdc(vdc['name'])
            vdc_obj = VDC(self.vcloudClient, resource=vdc_resource)
            vapp_list = vdc_obj.list_resources(EntityType.VAPP)
            for vapp in vapp_list:
                vapp_name = vapp.get('name')
                vapp_resource = vdc_obj.get_vapp(vapp_name)
                vapp_obj = VApp(self.vcloudClient, resource=vapp_resource)

                log.info(f"Get Information About vAppNetwork for VApp: '{vapp_name}'")
                try:
                    vapp_net = vapp_obj.get_vapp_network_list()
                except:
                    log.error(f"Fail Get networking information for vApp:'{vapp_name}'")
                    pass
                    
                for vnet in vapp_net: 
                    try:                   
                        vnet_data = vdc_obj.get_routed_orgvdc_network(vnet['name'])                    
                        self.vdc_network_info[vnet['name']] = self.get_vcd_network(vnet_data)
                    except:
                        log.debug(f"Fail get data For routed_orgvdc_network'{vnet['name']}'")

                vm_resource = vapp_obj.get_all_vms()
                log.debug(f"Found '{len(vm_resource)}' vm in '{vapp_name}'")
                
                log.info(f"Get vm data from vApp '{vapp_name}'")
                for vm_res in vm_resource:
                    self.add_virtual_machine(vm_res,vdc['name'])        

        #for view_name, view_details in object_mapping.items():
        self.update_basic_data()
        self.vcloudClient.logout()


    def add_necessary_base_objects(self):
        """
        Adds/updates source tag and all custom fields necessary for this source.
        """

        # add source identification tag
        self.inventory.add_update_object(NBTag, data={
            "name": self.source_tag,
            "description": f"Marks objects synced from vcloud director '{self.name}' to this NetBox Instance."
        })

    def create_api_session(self):
        #print(settings)
        log.info(f"Create API session for '{self.name}'")
        requests.packages.urllib3.disable_warnings()
        client = Client(self.vcloud_url,
            verify_ssl_certs=self.validate_tls_certs,
            log_file='pyvcloud.log',
            log_requests=True,
            log_headers=True,
            log_bodies=True)
        client.set_highest_supported_version()
        client.set_credentials(BasicLoginCredentials(self.username, self.vcloud_org, self.password))
        self.vcloudClient = client

    def get_vcloud_org(self, client):
        org_resource = client.get_org()
        return Org(client, resource=org_resource)        

    def get_vdc_list(self, org):
        vdc_list = org.list_vdcs()
        return vdc_list

    def get_vapp(self, vdc):
        vapp_list = False
        return vapp_list

    @staticmethod
    def passes_filter(name, include_filter, exclude_filter):
        """
        checks if object name passes a defined object filter.

        Parameters
        ----------
        name: str
            name of the object to check
        include_filter: regex object
            regex object of include filter
        exclude_filter: regex object
            regex object of exclude filter

        Returns
        -------
        bool: True if all filter passed, otherwise False
        """

        # first includes
        if include_filter is not None and not include_filter.match(name):
            log.debug(f"Object '{name}' did not match include filter '{include_filter.pattern}'. Skipping")
            return False

        # second excludes
        if exclude_filter is not None and exclude_filter.match(name):
            log.debug(f"Object '{name}' matched exclude filter '{exclude_filter.pattern}'. Skipping")
            return False

        return True


    def get_object_relation(self, name, relation, fallback=None):
        """

        Parameters
        ----------
        name: str
            name of the object to find a relation for
        relation: str
            name of the config variable relation (i.e: vm_tag_relation)
        fallback: str
            fallback string if no relation matched

        Returns
        -------
        data: str, list, None
            string of matching relation or list of matching tags
        """

        resolved_list = list()
        for single_relation in grab(self, relation, fallback=list()):
            object_regex = single_relation.get("object_regex")
            if object_regex.match(name):
                resolved_name = single_relation.get("assigned_name")
                log.debug2(f"Found a matching {relation} '{resolved_name}' ({object_regex.pattern}) for {name}.")
                resolved_list.append(resolved_name)

        if grab(f"{relation}".split("_"), "1") == "tag":
            return resolved_list

        else:
            resolved_name = fallback
            if len(resolved_list) >= 1:
                resolved_name = resolved_list[0]
                if len(resolved_list) > 1:
                    log.debug(f"Found {len(resolved_list)} matches for {name} in {relation}."
                              f" Using first on: {resolved_name}")

            return resolved_name


    def get_site_name(self, object_type, object_name, cluster_name=""):
        """
        Return a site name for a NBCluster or NBDevice depending on config options
        host_site_relation and cluster_site_relation

        Parameters
        ----------
        object_type: (NBCluster, NBDevice)
            object type to check site relation for
        object_name: str
            object name to check site relation for
        cluster_name: str
            cluster name of NBDevice to check for site name

        Returns
        -------
        str: site name if a relation was found
        """

        if object_type not in [NBCluster, NBDevice]:
            raise ValueError(f"Object must be a '{NBCluster.name}' or '{NBDevice.name}'.")

        log.debug2(f"Trying to find site name for {object_type.name} '{object_name}'")

        # check if site was provided in config
        relation_name = "host_site_relation" if object_type == NBDevice else "cluster_site_relation"

        site_name = self.get_object_relation(object_name, relation_name)

        if object_type == NBDevice and site_name is None:
            site_name = self.permitted_clusters.get(cluster_name) or \
                        self.get_site_name(NBCluster, object_name, cluster_name)
            log.debug2(f"Found a matching cluster site for {object_name}, using site '{site_name}'")

        # set default site name
        if site_name is None:
            site_name = self.site_name
            log.debug(f"No site relation for '{object_name}' found, using default site '{site_name}'")

        return site_name


    def get_object_based_on_macs(self, object_type, mac_list=None):
        """
        Try to find a NetBox object based on list of MAC addresses.

        Iterate over all interfaces of this object type and compare MAC address with list of desired MAC
        addresses. If match was found store related machine object and count every correct match.

        If exactly one machine with matching interfaces was found then this one will be returned.

        If two or more machines with matching MACs are found compare the two machines with
        the highest amount of matching interfaces. If the ration of matching interfaces
        exceeds 2.0 then the top matching machine is chosen as desired object.

        If the ration is below 2.0 then None will be returned. The probability is to low that
        this one is the correct one.

        None will also be returned if no machine was found at all.

        Parameters
        ----------
        object_type: (NBDevice, NBVM)
            type of NetBox device to find in inventory
        mac_list: list
            list of MAC addresses to compare against NetBox interface objects

        Returns
        -------
        (NBDevice, NBVM, None): object instance of found device, otherwise None
        """

        object_to_return = None

        if object_type not in [NBDevice, NBVM]:
            raise ValueError(f"Object must be a '{NBVM.name}' or '{NBDevice.name}'.")

        if mac_list is None or not isinstance(mac_list, list) or len(mac_list) == 0:
            return

        interface_typ = NBInterface if object_type == NBDevice else NBVMInterface

        objects_with_matching_macs = dict()
        matching_object = None

        for interface in self.inventory.get_all_items(interface_typ):

            if grab(interface, "data.mac_address") in mac_list:

                matching_object = grab(interface, f"data.{interface.secondary_key}")
                if not isinstance(matching_object, (NBDevice, NBVM)):
                    continue

                log.debug2("Found matching MAC '%s' on %s '%s'" %
                           (grab(interface, "data.mac_address"), object_type.name,
                            matching_object.get_display_name(including_second_key=True)))

                if objects_with_matching_macs.get(matching_object) is None:
                    objects_with_matching_macs[matching_object] = 1
                else:
                    objects_with_matching_macs[matching_object] += 1

        # try to find object based on amount of matching MAC addresses
        num_devices_witch_matching_macs = len(objects_with_matching_macs.keys())

        if num_devices_witch_matching_macs == 1 and isinstance(matching_object, (NBDevice, NBVM)):

            log.debug2("Found one %s '%s' based on MAC addresses and using it" %
                       (object_type.name, matching_object.get_display_name(including_second_key=True)))

            object_to_return = list(objects_with_matching_macs.keys())[0]

        elif num_devices_witch_matching_macs > 1:

            log.debug2(f"Found {num_devices_witch_matching_macs} {object_type.name}s with matching MAC addresses")

            # now select the two top matches
            first_choice, second_choice = \
                sorted(objects_with_matching_macs, key=objects_with_matching_macs.get, reverse=True)[0:2]

            first_choice_matches = objects_with_matching_macs.get(first_choice)
            second_choice_matches = objects_with_matching_macs.get(second_choice)

            log.debug2(f"The top candidate {first_choice.get_display_name()} with {first_choice_matches} matches")
            log.debug2(f"The second candidate {second_choice.get_display_name()} with {second_choice_matches} matches")

            # get ratio between
            matching_ration = first_choice_matches / second_choice_matches

            # only pick the first one if the ration exceeds 2
            if matching_ration >= 2.0:
                log.debug2(f"The matching ratio of {matching_ration} is high enough "
                           f"to select {first_choice.get_display_name()} as desired {object_type.name}")
                object_to_return = first_choice
            else:
                log.debug2("Both candidates have a similar amount of "
                           "matching interface MAC addresses. Using NONE of them!")

        return object_to_return

    def get_object_based_on_primary_ip(self, object_type, primary_ip4=None, primary_ip6=None):
        """
        Try to find a NBDevice or NBVM based on the primary IP address. If an exact
        match was found the device/vm object will be returned immediately without
        checking of the other primary IP address (if defined).

        Parameters
        ----------
        object_type: (NBDevice, NBVM)
            object type to look for
        primary_ip4: str
            primary IPv4 address of object to find
        primary_ip6: str
            primary IPv6 address of object to find

        Returns
        -------

        """

        def _matches_device_primary_ip(device_primary_ip, ip_needle):

            ip = None
            if device_primary_ip is not None and ip_needle is not None:
                if isinstance(device_primary_ip, dict):
                    ip = grab(device_primary_ip, "address")

                elif isinstance(device_primary_ip, int):
                    ip = self.inventory.get_by_id(NBIPAddress, nb_id=device_primary_ip)
                    ip = grab(ip, "data.address")

                if ip is not None and ip.split("/")[0] == ip_needle:
                    return True

            return False

        if object_type not in [NBDevice, NBVM]:
            raise ValueError(f"Object must be a '{NBVM.name}' or '{NBDevice.name}'.")

        if primary_ip4 is None and primary_ip6 is None:
            return

        if primary_ip4 is not None:
            primary_ip4 = str(primary_ip4).split("/")[0]

        if primary_ip6 is not None:
            primary_ip6 = str(primary_ip6).split("/")[0]

        for device in self.inventory.get_all_items(object_type):

            if _matches_device_primary_ip(grab(device, "data.primary_ip4"), primary_ip4) is True:
                log.debug2(f"Found existing host '{device.get_display_name()}' "
                           f"based on the primary IPv4 '{primary_ip4}'")
                return device

            if _matches_device_primary_ip(grab(device, "data.primary_ip6"), primary_ip6) is True:
                log.debug2(f"Found existing host '{device.get_display_name()}' "
                           f"based on the primary IPv6 '{primary_ip6}'")
                return device

    def add_datacenter(self, obj):
        """
        Add a cloud director org as a NBClusterGroup to NetBox

        Parameters
        ----------
        obj: name: value

        """        
        name = get_string_or_none(grab(obj, "name"))

        if name is None:
            return

        log.debug(f"Parsing cloud director org: {name}")

        self.inventory.add_update_object(NBClusterGroup, data={"name": name}, source=self)

    def add_cluster(self, obj, group):
        """
        Add a vCloud director VDC as a NBCluster to NetBox. Cluster name is checked against
        cluster_include_filter and cluster_exclude_filter config setting. Also adds
        cluster and site_name to "self.permitted_clusters" so hosts and VMs can be
        checked if they are part of a permitted cluster.

        Parameters
        ----------
        obj: vim.ClusterComputeResource
            cluster to add
        """

        name = get_string_or_none(grab(obj, "name"))

        #site_name = self.get_object_relation(name, 'cluster_site_relation')

        #group = get_string_or_none(grab(obj, "parent.parent.name"))

        if name is None or group is None:
            return

        log.debug(f"Parsing vcloud VDC: {name}")
        # need add filter
        #if self.passes_filter(name, self.vdc_include_filter, self.vdc_exclude_filter) is False:
        #    return
        
        site_name = self.get_site_name(NBCluster, name)       
        log.debug(f"Try get '{self.vcloud_org}' site_relation for '{self.cluster_site_relation}'  is a '{site_name}'")

        data = {
            "name": name,
            "type": {"name": "vCloud director VDC"},
            "group": {"name": group},
            "site": {"name": site_name}
        }
        
        tenant_name = self.get_object_relation(name, "cluster_tenant_relation")
        if tenant_name is not None:
            data["tenant"] = {"name": tenant_name}
        #
        self.inventory.add_update_object(NBCluster, data=data, source=self)

        self.permitted_clusters[name] = site_name
    

    def get_vcd_network(self, vnet_data: objectify.ObjectifiedElement):
        
        log.debug(f"Get prefix for Vcd Network....")
        xmlRaw = etree.tostring(vnet_data)
        vnet_dict = xmltodict.parse(xmlRaw)
        subPrefix = vnet_dict.get('OrgVdcNetwork',{}).get('Configuration',{}).get('IpScopes',{}).get('IpScope',{}).get('SubnetPrefixLength',{})
        gw = vnet_dict.get('OrgVdcNetwork',{}).get('Configuration',{}).get('IpScopes',{}).get('IpScope',{}).get('Gateway',{})   
        name = vnet_dict.get('OrgVdcNetwork',{}).get('@name', None)         
        #print(f"mask:{mask}")
        network = IPv4Network(f"{gw}/{subPrefix}",strict=False)
        
        return network
        #self.inventory.add_update_object(NBPrefix, data=data, source=self)
    

    def add_virtual_machine(self, vm_res, cluster_name):
        """
        Parse a VDC VM add to NetBox once all data is gathered.

        Parameters
        ----------
        obj: 
            virtual machine object to parse
        """
        log.debug(f"Get vm data ....")
        vapp_vm = VM(self.vcloudClient, resource=vm_res)
        #vmName = 
        #allvm_org_list[vdc_name][vapp_name].append({
 

        # check VM cluster
        if cluster_name is None:
            log.error(f"Requesting cluster for Virtual Machine in cluster '{cluster_name}' failed. Skipping.")
            return
        vm_data = {
            'name'    : vm_res.attrib["name"], 
            'status'  : "active" if vapp_vm.is_powered_on() else "offline",
            "cluster": {"name": cluster_name},
        }
        site_name = self.get_site_name(NBDevice, vm_data["name"], cluster_name)
        
        if site_name is not None:
            vm_data["cluster"]["site"] = {"name": site_name}
            # Add adaption for change in NetBox 3.3.0 VM model
            # issue: https://github.com/netbox-community/netbox/issues/10131#issuecomment-1225783758
            if version.parse(self.inventory.netbox_api_version) >= version.parse("3.3.0"):
                vm_data["site"] = {"name": site_name}

        else:
            log.warning(f"can't find Site for VM: '{vm_data}'")
        disk_size = 0
        tenant_name = self.get_object_relation(cluster_name, "cluster_tenant_relation")
        log.debug(f"Tenamt for VM: '{vm_data['name']}' is: '{tenant_name}'")
        for hw_element in vapp_vm.list_virtual_hardware_section(is_disk=True):
            vcpus = grab(hw_element,'cpuVirtualQuantity')
            if vcpus:
                vm_data['vcpus'] = int(vcpus) 
            memory = grab(hw_element,'memoryVirtualQuantityInMb')
            if memory:            
                #log.debug(f"type of var memory: '{memory.pytype}'")
                vm_data['memory'] = int(memory)
            if grab(hw_element,'diskElementName'):
                disk_size += grab(hw_element,'diskVirtualQuantityInBytes')
            if tenant_name is not None:
                vm_data["tenant"] = {"name": tenant_name}

        # get disk size in GB
        p = math.pow(1024, 3)
        if version.parse(self.inventory.netbox_api_version) < version.parse("3.7.0"):
            vm_data['disk'] = round(disk_size / p)
        # get vm platform Data
        vm_data['platform'] = {"name": str(grab(vapp_vm.list_os_section(),'Description'))}
        vm_primary_ip4 = None
        vm_nic_dict = dict()
        nic_ips = dict()       
        for nic in vapp_vm.list_nics():
            network = grab(nic,'network','.','Unknown')
            prefix = None
            #if nic_ips[network] is None:
            nic_ips[network] = list()
            ip_addr = grab(nic,'ip_address')
            prefixNet = self.vdc_network_info.get(network,None)
            if ip_addr is None:
                log.debug(f"IP is None for '{nic}' Skeeping")
                continue
            ip_vm = ip_interface(ip_addr)
            # set prefix only from Edge GW
            if prefixNet is None:            
                matched_prefix = self.return_longest_matching_prefix_for_ip(ip_vm, site_name)
                prefix = 32 if matched_prefix is None else matched_prefix.data["prefix"].prefixlen
            else:
                prefix = prefixNet.prefixlen    
            ip_addr = f"{ip_addr}/{prefix}"

            nic_ips[network].append(ip_addr)
            vm_primary_ip4 = ip_addr 

            mac_addr = grab(nic,'mac_address')
            full_name = unquote(f"vNIC{grab(nic,'index')} ({network})")
            vm_nic_data = {
                "name": full_name,
                "virtual_machine": None,
                "mac_address": normalize_mac_address(mac_addr),
                "description": full_name,
                "enabled": bool(grab(nic,'connected'))
            }
            if ip_valid_to_add_to_netbox(ip_addr, self.permitted_subnets, self.excluded_subnets, full_name) is True:
                vm_nic_dict[network] = vm_nic_data
            else:
                log.debug(f"Virtual machine '{vm_data['name']}' address '{ip_addr}' is not valid to add. Skipping")
        # end for        
        log.debug(f"vm_data is '{vm_data}'")
        log.debug(f"vm_nic_data: {vm_nic_dict}")
        # add VM to inventory
        if vm_primary_ip4 is None:
            log.info(f"SKEEP add vm: '{vm_data['name']}', Primary IP is Nome")
            log.debug(f"FAIL get primary IP for vm:'{vm_data}'")
            return    
        log.debug(" create VM and interfases ")
        add_device_vm_to_inventory(NBVM, object_data=vm_data, vnic_data=vm_nic_dict,
                                        nic_ips=nic_ips, p_ipv4=vm_primary_ip4, p_ipv6=None)


    def update_basic_data(self):
        """
        Returns
        -------

        """

        # add source identification tag
        self.inventory.add_update_object(NBTag, data={
            "name": self.source_tag,
            "description": f"Marks objects synced from vCloud Director '{self.name}' "
                           f"({self.vcloud_org}) to this NetBox Instance."
        })

        # update virtual site if present
        this_site_object = self.inventory.get_by_data(NBSite, data={"name": self.site_name})

        if this_site_object is not None:
            this_site_object.update(data={
                "name": self.site_name,
                "comments": f"A default virtual site created to house objects "
                            "that have been synced from this vCloud Director instance "
                            "and have no predefined site assigned."
            })