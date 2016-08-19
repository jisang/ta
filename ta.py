#!/usr/bin/env bash

from __future__ import print_function
import boto3
import inspect
from termcolor import colored

whitelisted_ports = frozenset((
    25,   # smtp
    80,   # http
    443,  # https
    465,  # smtps
    ))

blacklisted_ports = frozenset((
    20,    # ftp-data
    21,    # ftp
    1433,  # mssql
    1434,  # mssql
    3306,  # mysql
    3389,  # rdp
    4333,  # minisql
    5432,  # postgresql
    5500,  # vnc
    ))

class Security(object):
    def __init__(self):
        self.clients = {}
        self.security_groups = {}

    def client(self, service):
        if service not in self.clients or not self.clients[service]:
            self.clients[service] = boto3.client(service)
        return self.clients[service]

    def _get_security_groups(self):
        service = 'ec2'
        if not self.security_groups:
            self.security_groups = self.client(service).describe_security_groups()['SecurityGroups']
        
    def specific_ports_unrestricted(self):
        self._get_security_groups()
        for security_group in self.security_groups:
            for permissions in security_group['IpPermissions']:
                if {u'CidrIp': '0.0.0.0/0'} in permissions['IpRanges']:
                    if permissions['ToPort'] in blacklisted_ports:
                        yield colored(security_group, 'red', attrs=['bold'])
                        break
                    elif permissions['ToPort'] not in whitelisted_ports:
                        yield colored(security_group, 'yellow', attrs=['dark'])
                        break
            else:
                yield colored(security_group, 'green')

    def iam_use(self):
        service = 'iam'
        response = self.client(service).list_users(MaxItems=1)
        if not len(response['Users']):
            return colored(response, 'yellow', attrs=['dark'])
        else:
            return colored(response, 'green')

    def security_groups_unrestricted_access(self):
        self._get_security_groups()
        for security_group in self.security_groups:
            for permissions in security_group['IpPermissions']:
                for ip_range in permissions['IpRanges']:
                    if ip_range['CidrIp'][-2:] == '/0' and permissions['ToPort'] not in (25, 80, 443):
                        yield colored(security_group, 'red', attrs=['bold'])
                        break
            else:
                yield colored(security_group, 'green')

    def amazon_s3_bucket_permissions(self):
        service = 's3'
        return self.client(service).list_buckets()


def main():
    ts_s = Security()
    for sg in ts_s.specific_ports_unrestricted():
        print(sg)
    print(ts_s.iam_use())
    for sg in ts_s.security_groups_unrestricted_access():
        print(sg)
    for bucket in ts_s.amazon_s3_bucket_permissions()['Buckets']:
        print(bucket)

if __name__ == '__main__':
    main()
