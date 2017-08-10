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

instances = {}
def get_instance(ec2, instance_id):
    try:
        return instances[instance_id]
    except KeyError:
        print "Getting instance %s" % instance_id
        instances[instance_id] = ec2.Instance(instance_id)
        return instances[instance_id]


def get_cf_outputs(session, stack_name):
    # Get all the outputs for the stack
    cloudformation = session.client('cloudformation')
    response = cloudformation.describe_stacks(StackName=stack_name)
    outputs = {}
    for output in response['Stacks'][0]['Outputs']:
        outputs[output['OutputKey']] = output['OutputValue']

    return outputs


def put_job_metric(cloudwatch, server_stack, stack_name, job_id, task_name, name, value, unit):
    # Jobs are recorded under the ASG stack name, and also under the server stack name
    # The are required under the serer_stack name because the autoscaling task happens against
    #   the cloudformation metrics from the server_stack namespace
    response = cloudwatch.put_metric_data(
        Namespace='Nomad/%s' % server_stack,
        MetricData=[{
            'MetricName': name,
            'Dimensions': [{ 'Name': 'Job', 'Value': "%s::%s" % (job_id, task_name) }],
            'Value': value,
            'Unit': unit
            }])


def put_asg_metric(cloudwatch, asg, stack_name, name, value, unit):
    response = cloudwatch.put_metric_data(
        Namespace='Nomad/%s' % stack_name,
        MetricData=[{
            'MetricName': name,
            'Dimensions': [{ 'Name': 'AutoScalingGroupName', 'Value': asg }],
            'Value': value,
            'Unit': unit
            }])

    print "Pushed metric Nomad/%s AutoScalingGroupName:%s" % (stack_name, asg)

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
        instance = get_instance(ec2, instance_id)
        #instance = ec2.Instance(instance_id)
        instance_ips.append(instance.private_ip_address)

    return instance_ips

def push_job_stats(session, stack_name, nomad, consul, quiet):
    cloudwatch = session.client('cloudwatch')
    outputs = get_cf_outputs(session, stack_name)

    # Job statistics are recorded under the server stack also
    server_stack = outputs['ServerStack']

    # call nomad to find the list of jobs that exist
    try:
        json = requests.get('%s/v1/jobs' % (nomad), timeout=10).json()
    except ValueError:
        print "Invalid JSON Resposne from nomad server (Could not push_job_stats())"
        return False

    # TODO, this should run in its own thread for each job
    for job in json:
        try:
            if job['Stop'] == True:
                continue
        except:
            pass

        #print "Getting stats for Noamd Job ID: %s" % job['ID']
        allocations = requests.get('%s/v1/job/%s/allocations' % (nomad, job['ID']), timeout=10).json()

        # TODO, this should run in its own thread for each allocation
        for allocation in allocations:
            if allocation['ClientStatus'] != 'running':
                continue

            task_name = allocation['TaskGroup']

            # Now find out which node IP address this allocation is running on
            node = requests.get('%s/v1/node/%s' % (nomad, allocation['NodeID']), timeout=10).json()
            node_nomad_url = "http://%s" % node['HTTPAddr']

            # perform 3 requests in order to get a good sample size
            for i in range(3):
                # Now get the CPU information about this allocation
                # on the actual client
                #print '%s/v1/client/allocation/%s/stats' % (node_nomad_url, allocation['ID'])
                client_stats = requests.get('%s/v1/client/allocation/%s/stats' % (node_nomad_url, allocation['ID']), timeout=10).json()

                percent_cpu = client_stats['ResourceUsage']['CpuStats']['Percent']

                put_job_metric(cloudwatch, server_stack, stack_name, job['ID'], task_name, 'AverageCpuPercent', percent_cpu, 'Percent')
                print "Job(%s-%d) %s::%s %s%% CPU" % (allocation['ID'], i, job['ID'], task_name, percent_cpu)
                time.sleep(0.2)


def push_asg_stats(session, asg, stack_name, nomad, consul, quiet):
    print "push_asg_stats(session, %s, %s, %s, %s, quiet)" % (asg, stack_name, nomad, consul)
    cloudwatch = session.client('cloudwatch')

    instance_ips = get_instance_ips_from_asg(session, asg)

    total_cpu = 0
    total_memory = 0
    total_iops = 0
    total_disk = 0

    jobs_requested_cpu = 0
    jobs_requested_memory = 0
    jobs_requested_iops = 0
    jobs_requested_disk = 0

    # for each instance_ip get the stats by calling the nomad API against it
    for instance_ip in instance_ips:
        node_nomad_url = 'http://%s:4646' % instance_ip

        try:
            json = requests.get('%s/v1/agent/self' % (node_nomad_url), timeout=10).json()
        except ValueError:
            print "Could not get stats for self, node_id %s, skipping it" % node_id
            continue

        node_id = json['stats']['client']['node_id']

        try:
            json = requests.get('%s/v1/node/%s' % (node_nomad_url, node_id), timeout=10).json()
        except ValueError:
            print "Could not get stats for node_id %s, skipping it" % node_id
            continue

        node_name = json['Name']
        resources_cpu = json['Resources']['CPU']
        resources_memory = json['Resources']['MemoryMB']
        resources_iops = json['Resources']['IOPS']
        resources_disk = json['Resources']['DiskMB']

        total_cpu += resources_cpu
        total_memory += resources_memory
        total_iops += resources_iops
        total_disk += resources_disk

    # TODO this does not do any matching to ensure that the job will run
    #      on this specific cluster, and because of that if you have multiple
    #      clusters these numbers won't add up

    # now get the total number of jobs created
    # and show their total requested MemoryUtilization, CPU etc..
    try:
        jobs_json = requests.get('%s/v1/jobs' % nomad, timeout=10).json()
    except ValueError:
        print "Could not get job list from nomad server %s/v1/jobs" % nomad
        return False

    for job in jobs_json:
        try:
            if job['Stop'] == True:
                continue
        except:
            pass

        # for each job, get the job definition
        job_json = requests.get('%s/v1/job/%s' % (nomad, job['ID'])).json()

        # But only find the tasks where the LTarget is "${meta.aws_stack_name}"
        # and RTarget is the stack_name
        found_stack_constraint = False
        try:
            for constraint in job_json['Constraints']:
                if constraint['LTarget'] == '${meta.aws_stack_name}' and constraint['RTarget'] == stack_name:
                    found_stack_constraint = True
                    break
        except:
            pass

        if not found_stack_constraint:
            print 'Job %s does not have ${meta.aws_strack_name} constraint %s' % (job['ID'], stack_name)
            continue

        # now calculate the total count of task groups, and the Memory/CPU usage
        # in each taskgroup

        job_memory = 0
        job_cpu = 0
        job_iops = 0
        job_disk = 0

        for taskgroup in job_json['TaskGroups']:
            count = taskgroup['Count']

            for task in taskgroup['Tasks']:
                job_memory += task['Resources']['MemoryMB'] * count
                job_cpu += task['Resources']['CPU'] * count
                job_disk += task['Resources']['DiskMB'] * count
                job_iops += task['Resources']['IOPS'] * count

        if not quiet:
            print "Total requested for job %s: %s CPU, %s MemoryMB, %s IOPS, %s Disk" % (
                job['ID'], job_cpu, job_memory, job_iops, job_disk)

        jobs_requested_cpu += job_cpu
        jobs_requested_memory += job_memory
        jobs_requested_iops += job_iops
        jobs_requested_disk += job_disk

    if not quiet:
        print "Requested/Available: %s/%s CPU, %s/%s MemoryMB, %s/%s IOPS, %s/%s DiskMB" % (
            jobs_requested_cpu, total_cpu,
            jobs_requested_memory, total_memory,
            jobs_requested_iops, total_iops,
            jobs_requested_disk, total_disk)

    try:
        percent_cpu = int(jobs_requested_cpu / total_cpu * 100)
    except ZeroDivisionError:
        percent_cpu = 0

    percent_resource = percent_cpu

    try:
        percent_memory = int(jobs_requested_memory / total_memory * 100)
    except ZeroDivisionError:
        percent_memory = 0

    if percent_memory > percent_resource:
        percent_resource = percent_memory

    try:
        percent_iops = int(jobs_requested_iops / total_iops * 100)
    except ZeroDivisionError:
        percent_iops = 0

    if percent_iops > percent_resource:
        percent_resource = percent_iops

    try:
        percent_disk = int(jobs_requested_disk / total_disk * 100)
    except ZeroDivisionError:
        percent_disk = 0

    if percent_disk > percent_resource:
        percent_resource = percent_disk

    if not quiet:
        print "Total consumed by jobs: %s%% Resource, %s%% CPU, %s%% MemoryMB, %s%% IOPS, %s%% Disk" % (
            percent_resource,
            percent_cpu,
            percent_memory,
            percent_iops,
            percent_disk)
        print "-"*30

    put_asg_metric(cloudwatch, asg, stack_name, 'ResourceUtilization', percent_resource, 'Percent')
    put_asg_metric(cloudwatch, asg, stack_name, 'MemoryUtilization', percent_memory, 'Percent')
    put_asg_metric(cloudwatch, asg, stack_name, 'CPUUtilization', percent_cpu, 'Percent')
    put_asg_metric(cloudwatch, asg, stack_name, 'IOPSUtilization', percent_iops, 'Percent')
    put_asg_metric(cloudwatch, asg, stack_name, 'DiskUtilization', percent_disk, 'Percent')

def fetch_job_stats(thread_name, stack_name, nomad, consul, quiet, region):
    session = boto3.session.Session(region_name=region)

    while True:
        try:
            push_job_stats(stack_name=stack_name, nomad=nomad, consul=consul, quiet=quiet, session=session)
        except:
            traceback.print_exc(file=sys.stdout)

        time.sleep(sleep_between_jobs)

def fetch_asg_stats(thread_name, asg, stack_name, nomad, consul, quiet, region):
    session = boto3.session.Session(region_name=region)

    while True:
        try:
            push_asg_stats(asg=asg, stack_name=stack_name, nomad=nomad, consul=consul, quiet=quiet, session=session)
        except ASGNotFoundException:
            traceback.print_exc(file=sys.stdout)
            time.sleep(sleep_between_jobs/2)
        except:
            traceback.print_exc(file=sys.stdout)

        time.sleep(sleep_between_jobs)

def watch_instance_termination(thread_name, topic_arn, asg, region):
    while True:
        try:
            instance_id = requests.get('http://169.254.169.254/latest/meta-data/instance-id', timeout=5).text

            session = boto3.session.Session(region_name=region)
            account_id = session.client('sts').get_caller_identity().get('Account')
            sns = session.client('sns')

            # keep checking until we get a spot termination time
            while requests.get("http://169.254.169.254/latest/meta-data/spot/termination-time", timeout=5).status_code != 200:
                time.sleep(5)

            print "Spot termination notice received"

            # if the spot will be terminated, then send an autoscaling:EC2_INSTANCE_TERMINATING message
            # to an SNS topic_arn, thus cleaning up this instance if necessary
            message = {
                "AccountId": account_id,
                "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING",
                "AutoScalingGroupName": asg,
                "Service": "AWS Auto Scaling",
                "EC2InstanceId": instance_id
            }

            print "Sending SNS message to topic_arn %s: %s" % (topic_arn, message)
            sns.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message)
            )

            return
        except:
            traceback.print_exc(file=sys.stdout)
            time.sleep(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Show nomad agent allocation status')

    parser.add_argument('--quiet', required=False, default=False, action='store_true', help='No output')
    parser.add_argument('--asg', required=False, help='AWS Autoscaling Group')
    parser.add_argument('--stack_name', required=False, help='The AWS stack name')
    parser.add_argument('--region', required=False, help='AWS Region')
    parser.add_argument('--nomad', required=False, default='http://localhost:4646', help='The URL of the nomad agent')
    parser.add_argument('--consul', required=False, default='http://localhost:8500', help='The URL of the nomad agent')
    parser.add_argument('--snstopic', required=False, help='Will send a autoscaling termination event to this topic')

    parser.add_argument('--noasgstats', required=False, default=False, help='Disable ASG stat collection', action='store_true')
    parser.add_argument('--nojobstats', required=False, default=False, help='Disable job stat collection', action='store_true')

    args = parser.parse_args()

    if not args.region:
        document = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document', timeout=10).json()
        args.region = document['region']

    if not args.asg:
        document = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document', timeout=10).json()
        instance_id = document['instanceId']

        # now get the ASG (aws:autoscaling:groupName) from the instance Tags
        session = boto3.session.Session(region_name=args.region)
        ec2 = session.resource('ec2')
        instance = get_instance(ec2, instance_id)
        #instance = ec2.Instance(instance_id)

        for tag in instance.tags:
            if tag['Key'] == 'aws:autoscaling:groupName':
                args.asg = tag['Value']

    if not args.stack_name:
        document = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document', timeout=10).json()
        instance_id = document['instanceId']

        # now get the ASG (aws:autoscaling:groupName) from the instance Tags
        session = boto3.session.Session(region_name=args.region)
        ec2 = session.resource('ec2')
        instance = get_instance(ec2, instance_id)
        #instance = ec2.Instance(instance_id)

        for tag in instance.tags:
            if tag['Key'] == 'aws:cloudformation:stack-name':
                args.stack_name = tag['Value']

    if not args.asg:
        raise Exception("Failed to get aws:autoscaling:groupName tag from Instance, use --asg instead")

    if not args.stack_name:
        raise Exception("Failed to get aws:cloudformation:stack-name tag from Instance, use --stack_name instead")

    threads = []

    if not args.noasgstats:
        # This thread fetches the ASG stats and pushes them to AWS Cloudwatch
        t1 = threading.Thread(target=fetch_asg_stats, args=("fetch_asg_stats", args.asg, args.stack_name, args.nomad, args.consul, args.quiet, args.region, ))
        t1.daemon = True
        t1.start()
        threads.append(t1)

    if not args.nojobstats:
        # This thread fetches the statistics of the CPU used percentage as an average
        # for the running jobs in the cluster
        t2 = threading.Thread(target=fetch_job_stats, args=("fetch_job_stats", args.stack_name, args.nomad, args.consul, args.quiet, args.region, ))
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

    # the root thread is also counted as a thread!
    while threading.active_count() > 1:
        try:
            time.sleep(0.1)
        except (KeyboardInterrupt, SystemExit):
            sys.exit()
