#!/usr/bin/env python3
# Pyvcloud Examples
#
# Copyright (c) 2017-2018 VMware, Inc. All Rights Reserved.
#
# This product is licensed to you under the
# Apache License, Version 2.0 (the "License").
# You may not use this product except in compliance with the License.
#
# This product may include a number of subcomponents with
# separate copyright notices and license terms. Your use of the source
# code for the these subcomponents is subject to the terms and
# conditions of the subcomponent's license, as noted in the LICENSE file.
#
# Illustrates how to list all vApps within a single vDC.
# https://github.com/vmware/pyvcloud/blob/master/pyvcloud/vcd/utils.py

import sys
import os.path

import xmltodict
import tomli
import requests

from pyvcloud.vcd.utils import vdc_to_dict
from pyvcloud.vcd.client import BasicLoginCredentials
from pyvcloud.vcd.client import Client
from pyvcloud.vcd.client import EntityType
from pyvcloud.vcd.org import Org
from pyvcloud.vcd.vdc import VDC
from pyvcloud.vcd.vapp import VApp
from pyvcloud.vcd.vm import VM
from pyvcloud.vcd.metadata import Metadata
from lxml import etree
from lxml import objectify
from pyvcloud.vcd import utils

from module.common.misc import grab, dump, get_string_or_none, plural

# Collect arguments.
conf_file = "pycloud.toml"
if os.path.exists(conf_file):
    with open(conf_file, mode="rb") as fp:
        config = tomli.load(fp)
    try:
        host     = config["host"]
        org      = config["org"]
        user     = config["user"]
        password = config["password"]
    except:
        print(f"Wrong confiig file {conf_file} format")
        sys.exit(1)
else:
    if len(sys.argv) != 5:
        print("Usage: python3 {0} host org user password ".format(sys.argv[0]))
        sys.exit(1)
    host = sys.argv[1]
    org = sys.argv[2]
    user = sys.argv[3]
    password = sys.argv[4]
    
#vdc = sys.argv[5]

# Disable warnings from self-signed certificates.
requests.packages.urllib3.disable_warnings()

# Login. SSL certificate verification is turned off to allow self-signed
# certificates.  You should only do this in trusted environments.
print("Logging in: host={0}, org={1}, user={2}".format(host, org, user))
client = Client(host,
                verify_ssl_certs=False,
                log_file='pyvcloud.log',
                log_requests=True,
                log_headers=True,
                log_bodies=True)
client.set_highest_supported_version()
client.set_credentials(BasicLoginCredentials(user, org, password))

print("Fetching Org...")
org_resource = client.get_org()
org = Org(client, resource=org_resource)
'''
for vdc_info in org.list_vdcs():
    name = vdc_info['name']
    href = vdc_info['href']
    print("VDC name: {0}\n    href: {1}".format(
        vdc_info['name'], vdc_info['href']))
    vdc = VDC(client, resource=org.get_vdc(vdc_info['name']))
    print("{0}{1}".format("Name".ljust(40), "Type"))
    print("{0}{1}".format("----".ljust(40), "----"))
    for resource in vdc.list_resources():
        print('%s%s' % (resource['name'].ljust(40), resource['type']))
'''

vdc_list = org.list_vdcs()

print("Fetching VDC...")

allvm_org_data = dict()

for vdc in vdc_list: 
    vdc_name = (vdc['name'])
    vdc_resource = org.get_vdc(vdc_name)
    vdc_cpu_frenzi = vdc_resource.VCpuInMhz2

    vdc = VDC(client, resource=vdc_resource)

    vdc_dict = vdc_to_dict(vdc_resource)
    #print(f"vdc Info is:'{vdc_dict}'")

    #storage_profiles = vdc.get_storage_profiles()
    for profile in vdc_dict.get('storage_profiles',None):
        #print(f"profile: {profile}")
        storage_profile = vdc.get_storage_profile(profile)

        raw_data = etree.tostring(storage_profile)
        storage_dict = xmltodict.parse(raw_data)
        storage_url = storage_dict.get('VdcStorageProfile').get('@href') 

        storage_data = vdc.client.get_resource(storage_url)

        #print(f" stprof is: {storage_data.__dict__}")
        break
    '''
    Сначала получаете список политик хранения с помощью функции get_storage_profiles() из модуля pyvcloud.vcd.vdc.
    Далее с помощью функции get_resource() из модуля pyvcloud.vcd.client запрашиваете данные используя url, 
    который находиться в атрибуте href политики хранения и получаете нужные данные Limit, StorageUsedMB.
    '''

    vapp_list = vdc.list_resources(EntityType.VAPP)
    #vnet_list = list()
    #vnet_list.append(vdc.list_orgvdc_direct_networks)
    #vnet_list.append(vdc.list_orgvdc_routed_networks)
    #vnet_list.append(vdc.list_orgvdc_isolated_networks)
    #print(f"vdc net is: '{vnet_list}'")
    vm_list = list()
    allvm_org_list = dict()
    allvm_org_list[vdc_name] = dict()
    print("Fetching vApps....")
    for vapp in vapp_list:
        vapp_name = vapp.get('name')
        vapp_resource = vdc.get_vapp(vapp_name)

        vapp_obj = VApp(client, resource=vapp_resource)

        #print(type(vm_resource))
        
        vapp_net = vapp_obj.get_vapp_network_list()
        for vnet in vapp_net:
            vnet_prop = list()
            vnet_data = vdc.get_routed_orgvdc_network(vnet['name'])

            if isinstance(vnet_data,objectify.ObjectifiedElement):
                
                vnet_config = vnet_data.get('Configuration',None)
                vnet_info = {
                    "mask": grab(vnet_data,'Configuration.IpScopes.IpScope.SubnetPrefixLength',fallback="Unknown"),
                    "gw"  : grab(vnet_data,'Configuration.IpScopes.IpScope.Gateway',fallback="Unknown"),
                    "name": grab(vnet,'name',fallback="Unknown")
                }
                #mask = vnet_dict.get('OrgVdcNetwork',{}).get('Configuration',{}).get('IpScopes',{}).get('IpScope',{}).get('SubnetPrefixLength',{})
                #gw   = vnet_dict.get('OrgVdcNetwork',{}).get('Configuration',{}).get('IpScopes',{}).get('IpScope',{}).get('Gateway',{})
                #name = vnet_dict.get('OrgVdcNetwork',{}).get('@name', None)
            print(f"NetInfo: {vnet_info}")
               

         
            #zmask = vnet_data.iter('IpScope')
            #zmask = vnet_data.xpath("./OrgVdcNetwork")
 
            #print(f"vDC net for '{vapp_name}':'{vnet['name']}' -- \nMask:'{xroot}'")
        #'''
        print("Fetching VM...")
        vm_resource = vapp_obj.get_all_vms()
        # get vapp vm count first
        allvm_org_list[vdc_name][vapp_name] = []
        vapp_vm = list()
        for vm_res in vm_resource:
            disk_data = list()
            vapp_vm = VM(client, resource=vm_res)
            vmDict = utils.vm_to_dict(vm_res)
            vmName = vmDict.get('name',None)
            vmDescription = vmDict.get('description',None)
            if vmDescription:
                print(f"description for {vmName} is: {vmDescription}")
            vm_storage_profiles = vapp_vm.list_storage_profile()
            vm_hardware = vapp_vm.list_virtual_hardware_section(is_disk=True)
            # get device info
            for vm_device in vm_hardware:
                if vm_device.get('diskElementName',False):
                    disk_data.append({
                        "name": vm_device.get("diskElementName"),
                        "size": int(vm_device.get('diskVirtualQuantityInBytes',0) / 1024 / 1024),
                        "description": '' #" / ".join( grab(vapp_vm.list_storage_profile(),'name' ) )                  
                    })
            for ind, val in enumerate(disk_data):
                val["description"] = f"storage profile: {vm_storage_profiles[ind].get('name','Unknown')}"

            #{'diskElementName': 'Hard disk 1', 'diskVirtualQuantityInBytes': 80530636800}        
            allvm_org_list[vdc_name][vapp_name].append({
                'id'      : (vmDict.get("id")).split(':').pop(),
                'name'    : vmName, 
                'active'  : vapp_vm.is_powered_on(),                
                #'hardware': vapp_vm.list_virtual_hardware_section(is_disk=True),
                'platform': vapp_vm.list_os_section(),
                #'network' : vapp_vm.list_nics()
                'disk'    : disk_data
            })
            
            
            #get_vm_metadata
            vm_osSection = vapp_vm.get_operating_system_section()
            vm_metadata = vapp_vm.get_metadata()
            vm_metadata_obg = Metadata(client=client,resource=vm_metadata)
            vm_metadata_res  = vm_metadata_obg.get_resource()
            vm_metadata_dict = utils.metadata_to_dict(vm_metadata_res)
            print(f"metadata_res:{utils.metadata_to_dict(vm_metadata_res)}")
            #break
        #print(type(vm_resource))
        break
#print(f"vm info is {allvm_org_list}")
# Log out.
print("Logging out")
client.logout()
