#!/usr/bin/env python2.7
from __future__ import division
import requests
import argparse
import boto3
import time
import sys
import traceback
from bson import json_util
import json

def put_metric(session, asg, name, value, unit):
    cloudwatch = session.client('cloudwatch')

    response = cloudwatch.put_metric_data(
    Namespace='Nomad/ASG',
    MetricData=[{
        'MetricName': name,
        'Dimensions': [{ 'Name': 'AutoScalingGroupName', 'Value': asg }],
        'Value': value,
        'Unit': unit
        }])

def get_instance_ips_from_asg(session, asg):
    autoscaling = session.client('autoscaling')
    ec2 = session.resource('ec2')

    groups = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg],
        MaxRecords=100
    )

    instance_ids = []
    for i in groups['AutoScalingGroups'][0]['Instances']:
        instance_ids.append(i['InstanceId'])

    instance_ips = []
    for instance_id in instance_ids:
        instance = ec2.Instance(instance_id)
        instance_ips.append(instance.private_ip_address)

    return instance_ips

def push_stats(session, asg, nomad, consul, quiet):

    cloudwatch = session.client('cloudwatch')

    instance_ips = get_instance_ips_from_asg(session, asg)

    total_cpu = 0
    total_memory = 0
    total_iops = 0

    total_allocated_cpu = 0
    total_allocated_memory = 0
    total_allocated_iops = 0

    # for each instance_ip get the stats by calling the nomad API against it
    for instance_ip in instance_ips:
        node_nomad_url = 'http://%s:4646' % instance_ip

        json = requests.get('%s/v1/agent/self' % (node_nomad_url)).json()
        node_id = json['stats']['client']['node_id']

        json = requests.get('%s/v1/node/%s' % (node_nomad_url, node_id)).json()

        node_name = json['Name']
        resources_cpu = json['Resources']['CPU']
        resources_memory = json['Resources']['MemoryMB']
        resources_iops = json['Resources']['IOPS']

        total_cpu += resources_cpu
        total_memory += resources_memory
        total_iops += resources_iops

        allocated_cpu = 0
        allocated_memory = 0
        allocated_iops = 0

        r = requests.get('%s/v1/node/%s/allocations' % (node_nomad_url, node_id))
        # print '%s/v1/node/%s/allocations' % (node_nomad_url, node_id)
        json = r.json()

        for x in json:
            if x['ClientStatus'] != 'running':
                continue

            allocated_cpu += x['Resources']['CPU']
            allocated_memory += x['Resources']['MemoryMB']
            allocated_iops += x['Resources']['IOPS']

        if not quiet:
            print "%s: %s/%s CPU, %s/%s MemoryMB, %s/%s IOPS" % (node_name,
                allocated_cpu, resources_cpu,
                allocated_memory, resources_memory,
                allocated_iops, resources_iops)

        total_allocated_cpu += allocated_cpu
        total_allocated_memory += allocated_memory
        total_allocated_iops += allocated_iops

    if not quiet:
        print "Total: %s/%s CPU, %s/%s MemoryMB, %s/%s IOPS" % (
            total_allocated_cpu, total_cpu,
            total_allocated_memory, total_memory,
            total_allocated_iops, total_iops)

    try:
        percent_cpu = int(total_allocated_cpu / total_cpu * 100)
    except ZeroDivisionError:
        percent_cpu = 0

    try:
        percent_memory = int(total_allocated_memory / total_memory * 100)
    except ZeroDivisionError:
        percent_memory = 0

    try:
        percent_iops = int(total_allocated_iops / total_iops * 100)
    except ZeroDivisionError:
        percent_iops = 0

    if not quiet:
        print "Total: %s%% CPU, %s%% MemoryMB, %s%% IOPS" % (
            percent_cpu,
            percent_memory,
            percent_iops)
        print "-"*30

    put_metric(session, asg, 'CPUUtilization', percent_cpu, 'Percent')
    put_metric(session, asg, 'MemoryUtilization', percent_memory, 'Percent')
    put_metric(session, asg, 'IOPSUtilization', percent_iops, 'Percent')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Show nomad agent allocation status')

    parser.add_argument('--quiet', required=False, default=False, action='store_true', help='No output')
    parser.add_argument('--asg', required=False, help='AWS Autoscaling Group')
    parser.add_argument('--region', required=False, help='AWS Region')
    parser.add_argument('--nomad', required=False, default='http://localhost:4646', help='The URL of the nomad agent')
    parser.add_argument('--consul', required=False, default='http://localhost:8500', help='The URL of the nomad agent')
    args = parser.parse_args()

    if not args.region:
        document = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document').json()
        args.region = document['region']

    session = boto3.session.Session(region_name=args.region)

    if not args.asg:
        document = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document').json()
        instance_id = document['instanceId']

        # now get the ASG (aws:autoscaling:groupName) from the instance Tags
        ec2 = session.resource('ec2')
        instance = ec2.Instance(instance_id)

        for tag in instance.tags:
            if tag['Key'] == 'aws:autoscaling:groupName':
                args.asg = tag['Value']

    if not args.asg:
        raise Exception("Failed to get aws:autoscaling:groupName tag from Instance, use --asg instead")


    while True:
        try:
            push_stats(asg=args.asg, nomad=args.nomad, consul=args.consul, quiet=args.quiet, session=session)
            time.sleep(60)
        except KeyboardInterrupt:
            sys.exit()
        except:
            traceback.print_exc(file=sys.stdout)
            time.sleep(1)
