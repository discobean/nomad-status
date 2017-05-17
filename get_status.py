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
import threading

sleep_between_jobs = 60

class ASGNotFoundException(Exception):
    pass

def put_job_metric(cloudwatch, job_id, name, value, unit):
    response = cloudwatch.put_metric_data(
        Namespace='Nomad/Job',
        MetricData=[{
            'MetricName': name,
            'Dimensions': [{ 'Name': 'JobId', 'Value': job_id }],
            'Value': value,
            'Unit': unit
            }])


def put_asg_metric(cloudwatch, asg, name, value, unit):
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
    try:
        for i in groups['AutoScalingGroups'][0]['Instances']:
            instance_ids.append(i['InstanceId'])
    except IndexError:
        raise ASGNotFoundException("No ASGs found with the name %s" % asg)

    instance_ips = []
    for instance_id in instance_ids:
        instance = ec2.Instance(instance_id)
        instance_ips.append(instance.private_ip_address)

    return instance_ips

def push_job_stats(session, nomad, consul, quiet):
    cloudwatch = session.client('cloudwatch')

    # call nomad to find the list of jobs that exist
    json = requests.get('%s/v1/jobs' % (nomad)).json()

    for job in json:
        total_percent_cpu = 0
        total_allocations = 0

        #print "Getting stats for Noamd Job ID: %s" % job['ID']
        allocations = requests.get('%s/v1/job/%s/allocations' % (nomad, job['ID'])).json()

        for allocation in allocations:
            if allocation['ClientStatus'] != 'running':
                continue

            # Now find out which node IP address this allocation is running on
            node = requests.get('%s/v1/node/%s' % (nomad, allocation['NodeID'])).json()
            node_nomad_url = "http://%s" % node['HTTPAddr']

            # perform 3 requests in order to get a good sample size
            for i in range(3):
                # Now get the CPU information about this allocation
                # on the actual client
                #print '%s/v1/client/allocation/%s/stats' % (node_nomad_url, allocation['ID'])
                client_stats = requests.get('%s/v1/client/allocation/%s/stats' % (node_nomad_url, allocation['ID'])).json()

                percent_cpu = client_stats['ResourceUsage']['CpuStats']['Percent']
                total_percent_cpu += percent_cpu
                total_allocations += 1
                time.sleep(0.2)

        try:
            summary_percent_cpu = int(total_percent_cpu / total_allocations)
        except ZeroDivisionError:
            summary_percent_cpu = 0

        if not quiet:
            print "Job %s %s%% CPU" % (job['ID'], summary_percent_cpu)

        put_job_metric(cloudwatch, job['ID'], 'AverageCpuPercent', summary_percent_cpu, 'Percent')


    pass

def push_asg_stats(session, asg, nomad, consul, quiet):
    cloudwatch = session.client('cloudwatch')

    instance_ips = get_instance_ips_from_asg(session, asg)

    total_cpu = 0
    total_memory = 0
    total_iops = 0
    total_disk = 0

    total_allocated_cpu = 0
    total_allocated_memory = 0
    total_allocated_iops = 0
    total_allocated_disk = 0

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
        resources_disk = json['Resources']['DiskMB']

        total_cpu += resources_cpu
        total_memory += resources_memory
        total_iops += resources_iops
        total_disk += resources_disk

        allocated_cpu = 0
        allocated_memory = 0
        allocated_iops = 0
        allocated_disk = 0

        r = requests.get('%s/v1/node/%s/allocations' % (node_nomad_url, node_id))
        # print '%s/v1/node/%s/allocations' % (node_nomad_url, node_id)
        json = r.json()

        for x in json:
            if x['ClientStatus'] != 'running':
                continue

            allocated_cpu += x['Resources']['CPU']
            allocated_memory += x['Resources']['MemoryMB']
            allocated_iops += x['Resources']['IOPS']
            allocated_disk += x['Resources']['DiskMB']

        if not quiet:
            print "%s: %s/%s CPU, %s/%s MemoryMB, %s/%s IOPS, %s/%s DiskMB" % (node_name,
                allocated_cpu, resources_cpu,
                allocated_memory, resources_memory,
                allocated_iops, resources_iops,
                allocated_disk, resources_disk)

        total_allocated_cpu += allocated_cpu
        total_allocated_memory += allocated_memory
        total_allocated_iops += allocated_iops
        total_allocated_disk += allocated_disk

    if not quiet:
        print "Total: %s/%s CPU, %s/%s MemoryMB, %s/%s IOPS, %s/%s DiskMB" % (
            total_allocated_cpu, total_cpu,
            total_allocated_memory, total_memory,
            total_allocated_iops, total_iops,
            total_allocated_disk, total_disk)

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

    try:
        percent_disk = int(total_allocated_disk / total_disk * 100)
    except ZeroDivisionError:
        percent_disk = 0

    if not quiet:
        print "Total: %s%% CPU, %s%% MemoryMB, %s%% IOPS, %s%% Disk" % (
            percent_cpu,
            percent_memory,
            percent_iops,
            percent_disk)
        print "-"*30

    put_asg_metric(cloudwatch, asg, 'MemoryUtilization', percent_memory, 'Percent')
    put_asg_metric(cloudwatch, asg, 'CPUUtilization', percent_cpu, 'Percent')
    put_asg_metric(cloudwatch, asg, 'IOPSUtilization', percent_iops, 'Percent')
    put_asg_metric(cloudwatch, asg, 'DiskUtilization', percent_disk, 'Percent')

def fetch_job_stats(thread_name, nomad, consul, quiet, region):
    session = boto3.session.Session(region_name=region)

    while True:
        try:
            push_job_stats(nomad=args.nomad, consul=args.consul, quiet=args.quiet, session=session)
            time.sleep(sleep_between_jobs)
        except:
            traceback.print_exc(file=sys.stdout)
            time.sleep(1)

def fetch_asg_stats(thread_name, asg, nomad, consul, quiet, region):
    session = boto3.session.Session(region_name=region)

    while True:
        try:
            push_asg_stats(asg=args.asg, nomad=args.nomad, consul=args.consul, quiet=args.quiet, session=session)
            time.sleep(sleep_between_jobs)
        except ASGNotFoundException:
            traceback.print_exc(file=sys.stdout)
            time.sleep(sleep_between_jobs/2)
        except:
            traceback.print_exc(file=sys.stdout)
            time.sleep(1)

def watch_instance_termination(thread_name, topic, asg, region):
    instance_id = requests.get('http://169.254.169.254/latest/meta-data/instance-id').text

    session = boto3.session.Session(region_name=region)
    account_id = session.client('sts').get_caller_identity().get('Account')
    sns = session.client('sns')

    topic_arn = "arn:aws:sns:%s:%s:%s" % (region, account_id, topic)

    # keep checking until we get a spot termination time
    while requests.get("http://169.254.169.254/latest/meta-data/spot/termination-time").status_code != 200:
        time.sleep(5)

    print "Spot termination notice received"

    # if the spot will be terminated, then send an autoscaling:EC2_INSTANCE_TERMINATING message
    # to an SNS topic, thus cleaning up this instance if necessary
    message = {
        "AccountId": account_id,
        "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING",
        "AutoScalingGroupName": asg,
        "Service": "AWS Auto Scaling",
        "EC2InstanceId": instance_id
    }

    print "Sending SNS message to topic %s: %s" % (topic, message)
    sns.publish(
        TopicArn=topic,
        Message=json.dumps(message)
    )

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Show nomad agent allocation status')

    parser.add_argument('--quiet', required=False, default=False, action='store_true', help='No output')
    parser.add_argument('--asg', required=False, help='AWS Autoscaling Group')
    parser.add_argument('--region', required=False, help='AWS Region')
    parser.add_argument('--nomad', required=False, default='http://localhost:4646', help='The URL of the nomad agent')
    parser.add_argument('--consul', required=False, default='http://localhost:8500', help='The URL of the nomad agent')
    parser.add_argument('--snstopic', required=False, help='Will send a autoscaling termination event to this topic')
    args = parser.parse_args()

    if not args.region:
        document = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document').json()
        args.region = document['region']

    if not args.asg:
        document = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document').json()
        instance_id = document['instanceId']

        # now get the ASG (aws:autoscaling:groupName) from the instance Tags
        session = boto3.session.Session(region_name=args.region)
        ec2 = session.resource('ec2')
        instance = ec2.Instance(instance_id)

        for tag in instance.tags:
            if tag['Key'] == 'aws:autoscaling:groupName':
                args.asg = tag['Value']

    if not args.asg:
        raise Exception("Failed to get aws:autoscaling:groupName tag from Instance, use --asg instead")

    threads = []

    # This thread fetches the ASG stats and pushes them to AWS Cloudwatch
    t1 = threading.Thread(target=fetch_asg_stats, args=("fetch_asg_stats", args.asg, args.nomad, args.consul, args.quiet, args.region, ))
    t1.daemon = True
    t1.start()
    threads.append(t1)

    # This thread fetches the statistics of the CPU used percentage as an average
    # for the running jobs in the cluster
    t2 = threading.Thread(target=fetch_job_stats, args=("fetch_job_stats", args.nomad, args.consul, args.quiet, args.region, ))
    t2.daemon = True
    t2.start()
    threads.append(t2)

    if args.snstopic:
        # This thread checks for spot instance termination, and if terminated sends an SNS message
        # to this queue, as if it were sent by an AWS Autoscaling termination hook
        t3 = threading.Thread(target=watch_instance_termination, args=("watch_instance_termination", args.snstopic, args.asg, args.region, ))
        t3.daemon = True
        t3.start()
        threads.append(t3)

    while threading.active_count() > 0:
        try:
            time.sleep(0.1)
        except (KeyboardInterrupt, SystemExit):
            sys.exit()
