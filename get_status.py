#!/usr/bin/env python2.7
from __future__ import division
import requests
import argparse
import boto3
import time
import sys
import traceback

def put_metric(client, instance_id, name, value, unit):
    response = client.put_metric_data(
    Namespace='Nomad/Metrics',
    MetricData=[{
        'MetricName': name,
        'Dimensions': [{ 'Name': 'InstanceId', 'Value': instance_id }],
        'Value': value,
        'Unit': unit
        }])

def push_stats(agent_url):
    json = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document').json()
    region = json['region']
    instance_id = json['instanceId']

    client = boto3.client('cloudwatch', region_name=region)

    r = requests.get('%s/v1/agent/self' % (agent_url))
    json = r.json()
    node_id = json['stats']['client']['node_id']
    datacenter = json['config']['Datacenter']
    region = json['config']['Region']

    r = requests.get('%s/v1/node/%s' % (agent_url, node_id))
    json = r.json()

    node_name = json['Name']
    resources_cpu = json['Resources']['CPU']
    resources_memory = json['Resources']['MemoryMB']
    resources_disk = json['Resources']['DiskMB']
    resources_iops = json['Resources']['IOPS']

    #print "nomad.%s.%s.%s.resources.total.CPU %s" % (region, datacenter, node_name, resources_cpu)
    #print "nomad.%s.%s.%s.resources.total.MemoryMB %s" % (region, datacenter, node_name, resources_memory)
    #print "nomad.%s.%s.%s.resources.total.DiskMB %s" % (region, datacenter, node_name, resources_disk)
    #print "nomad.%s.%s.%s.resources.total.IOPS %s" % (region, datacenter, node_name, resources_iops)

    # now get the allocations allocated to this

    allocated_cpu = 0
    allocated_memory = 0
    allocated_disk = 0
    allocated_iops = 0

    r = requests.get('%s/v1/node/ec29a71d-f68a-27d2-4b34-0207d0648dc8/allocations' % agent_url)
    json = r.json()

    for x in json:
        allocated_cpu += x['Resources']['CPU']
        allocated_memory += x['Resources']['MemoryMB']
        allocated_disk += x['Resources']['DiskMB']
        allocated_iops += x['Resources']['IOPS']

    #print "nomad.%s.%s.%s.resources.allocated.CPU %s" % (region, datacenter, node_name, allocated_cpu)
    #print "nomad.%s.%s.%s.resources.allocated.MemoryMB %s" % (region, datacenter, node_name, allocated_memory)
    #print "nomad.%s.%s.%s.resources.allocated.DiskMB %s" % (region, datacenter, node_name, allocated_disk)
    #print "nomad.%s.%s.%s.resources.allocated.IOPS %s" % (region, datacenter, node_name, allocated_iops)

    try:
        percent_cpu = int(allocated_cpu / resources_cpu * 100)
    except ZeroDivisionError:
        percent_cpu = 0

    try:
        percent_memory = int(allocated_memory / resources_memory * 100)
    except ZeroDivisionError:
        percent_memory = 0

    try:
        percent_disk = int(allocated_disk / resources_disk * 100)
    except ZeroDivisionError:
        percent_disk = 0

    try:
        percent_iops = int(allocated_iops / resources_iops * 100)
    except ZeroDivisionError:
        percent_iops = 0

    #print "nomad.%s.%s.%s.resources.allocated_percent.CPU %s" % (region, datacenter, node_name, percent_cpu)
    #print "nomad.%s.%s.%s.resources.allocated_percent.MemoryMB %s" % (region, datacenter, node_name, percent_memory)
    #print "nomad.%s.%s.%s.resources.allocated_percent.DiskMB %s" % (region, datacenter, node_name, percent_disk)
    #print "nomad.%s.%s.%s.resources.allocated_percent.IOPS %s" % (region, datacenter, node_name, percent_iops)

    put_metric(client, instance_id, 'UsedCpu', percent_cpu, 'Percent')
    put_metric(client, instance_id, 'UsedMemory', percent_memory, 'Percent')
    put_metric(client, instance_id, 'UsedDisk', percent_disk, 'Percent')
    put_metric(client, instance_id, 'UsedIOPS', percent_iops, 'Percent')

    #print "nomad.%s.%s.%s.resources.available_percent.CPU %s" % (region, datacenter, node_name, 100 - percent_cpu)
    #print "nomad.%s.%s.%s.resources.available_percent.MemoryMB %s" % (region, datacenter, node_name, 100 - percent_memory)
    #print "nomad.%s.%s.%s.resources.available_percent.DiskMB %s" % (region, datacenter, node_name, 100 - percent_disk)
    #print "nomad.%s.%s.%s.resources.available_percent.IOPS %s" % (region, datacenter, node_name, 100 - percent_iops)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Show nomad agent allocation status')

    parser.add_argument('--agent_url', required=False, default='http://localhost:4646', help='The URL of the nomad agent')
    args = parser.parse_args()

    while True:
        try:
            push_stats(args.agent_url)
            time.sleep(60)
        except:
            traceback.print_exc(file=sys.stdout)
            time.sleep(1)

