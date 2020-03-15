#!/usr/bin/env python3

# --- libraries ---
from bz2 import open as bzopen
import csv
from datetime import date, timedelta
import os
from queue import SimpleQueue
import threading
import time

# --- globals ---
dates = SimpleQueue()
outbox = SimpleQueue()
delta = timedelta(days = 2)
start_date = date(2011, 1, 21)
end_date = date(2020, 2, 29)
thread_count = 2
threads_running = True

# --- statistics ---
prefixes_lock = threading.Lock()
attacks_lock = threading.Lock()
prefixes = set()
v4_prefixes_advertised = 0
unique_v4_prefixes = 0
v6_prefixes_advertised = 0
unique_v6_prefixes = 0
attacks = dict()
attack_stats = dict()
num_v4_attacks = 0
num_v6_attacks = 0

# --- functions ---
def populate_date_queue():
    now = start_date
    while now <= end_date:
        dates.put(now)
        now += delta

def thread_safe_add(prefix, ip_type):
    global prefixes, v4_prefixes_advertised, v6_prefixes_advertised, unique_v4_prefixes, unique_v6_prefixes
    with prefixes_lock:
        if ip_type == '4':
            v4_prefixes_advertised += 1
            if prefix not in prefixes:
                unique_v4_prefixes += 1
        elif ip_type == '6':
            v6_prefixes_advertised += 1
            if prefix not in prefixes:
                unique_v6_prefixes += 1
        prefixes.add(prefix)

def thread_safe_update(prefix, num_actors):
    global attacks
    with attacks_lock:
        if prefix in attacks.keys():
            attacks[prefix] = max(num_actors, attacks[prefix])
        else:
            attacks[prefix] = num_actors

def get_num_actors(asns):
    asns = asns.split(',')
    count = 0
    i = 0
    while i < len(asns):
        if '{' in asns[i]:
            while '}' not in asns[i]:
                i += 1
        count += 1
        i += 1
    return count

def calculate_attack_stats():
    global attack_stats, attacks, num_v4_attacks, num_v6_attacks
    for key, value in attacks.items():
        if value in attack_stats.keys():
            attack_stats[value] += 1
        else:
            attack_stats[value] = 1
        if '.' in key:
            num_v4_attacks += 1
        elif ':' in key:
            num_v6_attacks += 1

def write_results():
    global v4_prefixes_advertised, v6_prefixes_advertised, unique_v4_prefixes, unique_v6_prefixes, attack_stats, num_v4_attacks, num_v6_attacks

    calculate_attack_stats()

    with open('./table.txt', 'w+') as f:
        f.write('prefixes\n')
        f.write('total v4 prefixes:  {:,}\n'.format(v4_prefixes_advertised))
        f.write('unique v4 prefixes: {:,}\n'.format(unique_v4_prefixes))
        f.write('total v6 prefixes:  {:,}\n'.format(v6_prefixes_advertised))
        f.write('unique v6 prefixes: {:,}\n'.format(unique_v6_prefixes))
        f.write('\nattacks\n')
        f.write('total v4 attacks:   {:,}\n'.format(num_v4_attacks))
        f.write('total v6 attacks:   {:,}\n'.format(num_v6_attacks))
        f.write('number of actors, number of attacks\n')
        for key, value in attack_stats.items():
            f.write('{0:02d}: {1:,}\n'.format(key, value))

def parser_target():
    global prefixes, attacks
    while True:
        try:
            now = dates.get(block = False, timeout = 0.125)
        except:
            return

        filename = '../route-views/{}.csv.bz2'.format(now)
        printed = False
        while not os.path.isfile(filename):
            if not printed:
                print('{} waiting for parse to finish'.format(now))
                printed = True
            time.sleep(10)
        
        print('{} summarizing'.format(now))
        start_time = time.time()

        num_v4_prefixes = 0
        num_v6_prefixes = 0
        num_unique_v4_prefixes = 0
        num_unique_v6_prefixes = 0
        num_v4_isolated = 0
        num_v6_isolated = 0
        num_v4_distributed = 0
        num_v6_distributed = 0
        seen_prefixes = set()
        attacked_prefixes = set()

        with bzopen(filename, 'rt') as f:
            reader = csv.reader(f)
            next(reader)
            for line in reader:
                ip_type = line[2]
                prefix = line[3]

                if ip_type == '4':
                    num_v4_prefixes += 1
                elif ip_type == '6':
                    num_v6_prefixes += 1
                seen_prefixes.add(prefix)
                thread_safe_add(prefix, ip_type)

                if line[5].rstrip() == 'I':
                    if prefix not in attacked_prefixes:
                        if ip_type == '4':
                            num_v4_isolated += 1
                        elif ip_type == '6':
                            num_v6_isolated += 1
                    thread_safe_update(prefix, 2)
                    attacked_prefixes.add(prefix)
                elif line[5].rstrip() == 'D':
                    if prefix not in attacked_prefixes:
                        if ip_type == '4':
                            num_v4_distributed += 1
                        elif ip_type == '6':
                            num_v6_distributed += 1
                    thread_safe_update(prefix, get_num_actors(line[4]))
                    attacked_prefixes.add(prefix)

        for prefix in seen_prefixes:
            with prefixes_lock:
                if prefix in prefixes:
                    if '.' in prefix:
                        num_unique_v4_prefixes += 1
                    elif ':' in prefix:
                        num_unique_v6_prefixes += 1
        end_time = time.time()
        print('{0} -- {1:.3f} sec'.format(now, end_time - start_time))

        record = '{0},{1},{2},{3},{4},{5},{6},{7},{8}\n'.format(
            now,
            num_v4_prefixes,
            num_unique_v4_prefixes,
            num_v6_prefixes,
            num_unique_v6_prefixes,
            num_v4_isolated,
            num_v6_isolated,
            num_v4_distributed,
            num_v6_distributed
        )

        outbox.put(record)
        del attacked_prefixes
        del seen_prefixes

def writer_target():
    global threads_running
    while threads_running == True:
        while outbox.empty() == True:
            time.sleep(2)
        if threads_running == False:
            break
        item = outbox.get()
        with open('./summarized.csv', 'a+') as f:
            f.write(item)

    while outbox.empty() == False:
        item = outbox.get()
        with open('./summarized.csv', 'a+') as f:
            f.write(item)


def main():
    global thread_count, threads_running

    populate_date_queue()

    writer = threading.Thread(target = writer_target)
    writer.start()
    
    threads = []
    for i in range(thread_count):
        threads.append(threading.Thread(target = parser_target))

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()
    threads_running = False

    writer.join()
    print('writing results')
    write_results()

# --- entry point ---
if __name__ == '__main__':
    main()
