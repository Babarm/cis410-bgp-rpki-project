#!/usr/bin/env python3

from datetime import date, timedelta
import os
import queue
from subprocess import Popen, PIPE, DEVNULL
import sys
import threading
import time
import requests
from paramiko import SSHClient
from scp import SCPClient

collectors = [
    ('route-views2', 'arin'),
    ('route-views3', 'arin'),
    ('route-views4', 'arin'),
    ('route-views6', 'arin'),
    ('route-views.amsix', 'ripe ncc'),
    ('route-views.chicago', 'arin'),
    ('route-views.chile', 'lacnic'),
    ('route-views.eqix', 'arin'),
    ('route-views.flix', 'arin'),
    ('route-views.fortaleza', 'lacnic'),
    ('route-views.gixa', 'lacnic'),
    ('route-views.gorex', 'arin'),
    ('route-views.isc', 'arin'),
    ('route-views.jinx', 'afrinic'),
    ('route-views.kixp', 'afrinic'),
    ('route-views.linx', 'ripe ncc'),
    ('route-views.mwix', 'arin'),
    ('route-views.napafrica', 'afrinic'),
    ('route-views.nwax', 'arin'),
    ('route-views.perth', 'apnic'),
    ('route-views.phoix', 'apnic'),
    ('route-views.rio', 'lacnic'),
    ('route-views.saopaulo', 'lacnic'),
    ('route-view2.saopaulo', 'lacnic'),
    ('route-views.sfmix', 'arin'),
    ('route-views.sg', 'apnic'),
    ('route-views.soxrs', 'ripe ncc'),
    ('route-views.sydney', 'apnic'),
    ('route-views.telxatl', 'arin'),
    ('route-views.wide', 'apnic'),
]

no_links = ['route-views.fortaleza', 'route-views.gixa', 'route-views.rio']

num_threads = 5

start_date = date(2011, 1, 21)
end_date = date(2020, 2, 29)
delta = timedelta(days = 2)

dates = queue.SimpleQueue()
date = start_date
while date <= end_date:
    dates.put(date)
    date += delta


def parser(name):
    while True:
        if dates.empty() == True:
            return
        date = dates.get()

        filename = './data/{0}.csv'.format(date.strftime('%Y-%m-%d'))
        thread_start = time.time()


        with open(filename, 'a+') as f:
            f.write('collector_name,rir,ip_type,prefix,origin_asns,attack_type\n')
        for collector in collectors:
            start = time.time()
            collector_name, rir = collector
            collector_name = '' if collector_name == 'route-views2' else collector_name

            # get file
            if collector_name in no_links:
                url_fmt = '/mnt/storage/{0}/bgpdata/{1}/RIBS/rib.{2}.bz2'
                url = url_fmt.format(collector_name, date.strftime('%Y.%m'), date.strftime('%Y%m%d.%H%M'))
                collector_name = 'route-views2' if collector_name == '' else collector_name
                print('{0} - {1} downloading file'.format(collector_name, date))
                ssh = SSHClient()
                ssh.load_system_host_keys()
                ssh.connect('archive.routeviews.org')
                scp = SCPClient(ssh.get_transport())
                try:
                    scp.get(url, local_path = name)
                except:
                    scp.close()
                    ssh.close()
                    print('SCP: {0} - {1} file not found'.format(collector_name, date))
                    continue
                scp.close()
                ssh.close()
            else:
                url_fmt = 'http://archive.routeviews.org/{0}/bgpdata/{1}/RIBS/rib.{2}.bz2'
                url = url_fmt.format(collector_name, date.strftime('%Y.%m'), date.strftime('%Y%m%d.%H%M'))
                collector_name = 'route-views2' if collector_name == '' else collector_name
                print('{0} - {1} downloading file'.format(collector_name, date))
                raw = requests.get(url)
                if raw.status_code != 200:
                    print('HTTP: {0} - {1} file not found'.format(collector_name, date))
                    continue
                with open(name, 'wb+') as f:
                    f.write(raw.content)

            print('{0} - {1} starting parse'.format(collector_name, date))

            # parse
            cmd = 'bgpreader -d singlefile -o rib-file={0}'.format(name).split(' ')

            prefixes = dict()
            with Popen(cmd, stdout = PIPE, stderr = DEVNULL, text = True) as parsed:
                for line in iter(parsed.stdout.readline, ''):
                    line = line.split('|')
                    try:
                        if line[9] in prefixes.keys():
                            prefixes[line[9]].add(line[12])
                        else:
                            prefixes[line[9]] = set()
                            prefixes[line[9]].add(line[12])
                    except:
                        continue
            
            print('{0} - {1} writing results'.format(collector_name, date))
            with open(filename, 'a+') as f:
                for prefix, asns in prefixes.items():
                    if prefix.endswith('/0'):
                        continue
                    attack = 'N' if len(asns) == 1 else ('I' if len(asns) == 2 else 'D')
                    af = '4' if '.' in prefix else '6'
                    f.write('{0},{1},{2},{3},"{4}",{5}\n'.format(
                        collector_name,
                        rir,
                        af,
                        prefix,
                        ','.join(asns),
                        attack
                    ))

            del prefixes

            os.system('rm {0}'.format(name))
            end = time.time()
            print('{0} - {1} {2:.3f} sec'.format(collector_name, date, end - start))

        print('{0} compressing'.format(date))
        os.system('bzip2 {0}'.format(filename))
        thread_end = time.time()
        print('{0} - {1} {2:.3f} sec'.format(name, date, thread_end - thread_start))
            

def main():
    threads = []
    for i in range(num_threads):
        thread = threading.Thread(target = parser, args = ('thread-{}'.format(i),))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

if __name__ == '__main__':
    main()
