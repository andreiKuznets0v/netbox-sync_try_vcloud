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

#from module.sources.common.source_base import SourceBase
from module.sources.vmware.connection import VMWareHandler
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
from pyvcloud.vcd.metadata import Metadata
from pyvcloud.vcd import utils

log = get_logger()


class CheckCloudDirector(VMWareHandler):
    """
    Source class to import Vcloud Director inventory files
    """

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
        self.processed_vm_names = dict()
        self.processed_vm_uuid = list()
        self.object_cache = dict()
        self.parsing_vms_the_first_time = True
        self.objects_to_reevaluate = list()
        self.parsing_objects_to_reevaluate = False

        
    def finish(self):

        # closing tag session
        if self.vcloudClient is not None:
            try:
                self.vcloudClient.logout()
            except Exception as e:
                log.error(f"unable to close API  connection: {e}")


    def apply(self):

        log.info(f"Query data from vCenter: '{self.settings.vcloud_url}'")
        """
        Main source handler method. This method is called for each source from "main" program
        to retrieve data from it source and apply it to the NetBox inventory.

        Every update of new/existing objects fot this source has to happen here.

        First try to find and iterate over each inventory file.
        Then parse the system data first and then all components.
        """
        # add tags
        #self.add_necessary_base_objects()
        
        object_mapping = {
            "datacenter": {
                "view_type": VDC,
                "view_handler": self.add_datacenter
            }
        }

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

    def create_api_session(self):
        #print(settings)
        log.info(f"Create API session for '{self.name}'")
        requests.packages.urllib3.disable_warnings()
        client = Client(self.settings.vcloud_url,
            verify_ssl_certs=self.settings.validate_tls_certs,
            log_file='pyvcloud.log',
            log_requests=True,
            log_headers=True,
            log_bodies=True)
        client.set_highest_supported_version()
        client.set_credentials(BasicLoginCredentials(self.settings.username, self.settings.vcloud_org, self.settings.password))
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
        log.debug(f"Try get '{self.settings.vcloud_org}' site_relation for '{self.settings.cluster_site_relation}'  is a '{site_name}'")

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
        vm_storage_profiles = vapp_vm.list_storage_profile()
 
        vm_dict = utils.vm_to_dict(vm_res)
        name = vm_dict.get('name', None)
        vm_uuid = get_string_or_none(vm_dict.get('name')).split(':').pop()
        if vm_uuid is None or vm_uuid in self.processed_vm_uuid and vm_res not in self.objects_to_reevaluate:
            return

        # add to processed VMs
        self.processed_vm_uuid.append(vm_uuid)

        # check VM cluster
        if cluster_name is None:
            log.error(f"Requesting cluster for Virtual Machine in cluster '{cluster_name}' failed. Skipping.")
            return

        # add vm to processed list
        if self.processed_vm_names.get(cluster_name) is None:
            self.processed_vm_names[cluster_name] = list()

        self.processed_vm_names[cluster_name].append(name)

        vm_data = {
            'name'    : name, 
            'status'  : "active" if vapp_vm.is_powered_on() else "offline",
            "cluster": {"name": cluster_name},
        }

        # Get site name
        site_name = self.get_site_name(NBDevice, name, cluster_name)
        if site_name is not None:
            vm_data["cluster"]["site"] = {"name": site_name}
            # Add adaption for change in NetBox 3.3.0 VM model
            # issue: https://github.com/netbox-community/netbox/issues/10131#issuecomment-1225783758
            if version.parse(self.inventory.netbox_api_version) >= version.parse("3.3.0"):
                vm_data["site"] = {"name": site_name}
        else:
            log.warning(f"can't find Site for VM: '{vm_data}'")
        
        # Get VM Description add to annotation
        annotation = None
        if self.settings.skip_vm_comments is False:
            annotation = get_string_or_none(vm_dict.get('description',None))
        if annotation is not None:
            vm_data["comments"] = annotation

        # Get vm metadata for NetBox custom fields
        if self.settings.sync_metadata:
            log.debug(f"Get metadata for VM: {name}")
            vm_metadata = vapp_vm.get_metadata()
            vm_metadata_obg = Metadata(self.vcloudClient,resource=vm_metadata)
            vm_metadata_res  = vm_metadata_obg.get_resource()
            vm_metadata_dict = utils.metadata_to_dict(vm_metadata_res)
            custom_field = None
            vm_custom_field = dict()
            for key,value in vm_metadata_dict.items():
                if self.settings.allowed_metadata_fields:
                    if key.lower() in self.settings.allowed_metadata_fields:
                        vm_custom_field[key.lower()] = value
                else:
                    vm_custom_field[key.lower()] = value
                log.debug(f"Create custom field {key.lower()} from VM {name} metadata")
                custom_field = self.add_update_custom_field({
                    "name": key.lower(),
                    "label": key,
                    "object_types": "virtualization.virtualmachine",
                    "type": "text"
                })
            if custom_field:    
                vm_data["custom_fields"] = vm_custom_field

        #'''
        # Aptein tenant info
        tenant_name = self.get_object_relation(cluster_name, "cluster_tenant_relation")
        if tenant_name is not None:
            vm_data["tenant"] = {"name": tenant_name}
        log.debug(f"Tenamt for VM: '{vm_data['name']}' is: '{tenant_name}'")
        # Grub hardware information
        disk_size = 0
        disk_data = list()
        
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
                disk_data.append({
                        "name": hw_element.get("diskElementName"),
                        "size": int(hw_element.get('diskVirtualQuantityInBytes',0) / 1024 / 1024),
                        "description": '' #" / ".join( grab(vapp_vm.list_storage_profile(),'name' ) )                  
                })
        for ind, val in enumerate(disk_data):
            val["description"] = f"storage profile: {vm_storage_profiles[ind].get('name','Unknown')}"

        # Set disk size in GB
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
            #if ip_valid_to_add_to_netbox(ip_addr, self.permitted_subnets, self.excluded_subnets, full_name) is True:
            vm_nic_dict[network] = vm_nic_data
            #else:
            #    log.debug(f"Virtual machine '{vm_data['name']}' address '{ip_addr}' is not valid to add. Skipping")
        # end for        
        log.debug(f"vm_data is '{vm_data}'")
        log.debug(f"vm_nic_data: {vm_nic_dict}")
        # add VM to inventory
        if vm_primary_ip4 is None:
            log.info(f"SKEEP add vm: '{vm_data['name']}', Primary IP is Nome")
            log.debug(f"FAIL get primary IP for vm:'{vm_data}'")
            return    
        log.debug(" create VM and interfases ")
        self.add_device_vm_to_inventory(NBVM, object_data=vm_data, vnic_data=vm_nic_dict,
                                        nic_ips=nic_ips, p_ipv4=vm_primary_ip4, p_ipv6=None, disk_data=disk_data)


    def update_basic_data(self):
        """
        Returns
        -------

        """

        # add source identification tag
        self.inventory.add_update_object(NBTag, data={
            "name": self.source_tag,
            "description": f"Marks objects synced from vCloud Director '{self.name}' "
                           f"({self.settings.vcloud_org}) to this NetBox Instance."
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