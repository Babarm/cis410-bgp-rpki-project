#!/usr/bin/env python3

import matplotlib.pyplot as plt
from datetime import datetime, date, timedelta

dates = []

advertisements = []
prefixes = []
attacks = []
isolated_attacks = []
distributed_attacks = []
isolated_percs = []
distributed_percs = []

with open('./summarized.csv', 'r') as f:
    f_iter = iter(f)
    next(f)
    for line in f_iter:
        line = line.split(',')

        num_advertisements = int(line[1]) + int(line[3])
        num_prefixes = int(line[2]) + int(line[4])
        advertisements.append(num_advertisements)
        prefixes.append(num_prefixes)

        num_attacks = int(line[5]) + int(line[6]) + int(line[7]) + int(line[8])
        isolated = int(line[5]) + int(line[6])
        distributed = int(line[7]) + int(line[8])
        attacks.append(num_attacks)
        isolated_attacks.append(isolated)
        distributed_attacks.append(distributed)

        isolated_percs.append(isolated / num_prefixes * 100)
        distributed_percs.append(distributed / num_prefixes * 100)

vrps = []
with open('../rpki/data.csv', 'r') as f:
    for line in f:
        d, v = line.split(',')
        d = datetime.strptime(d, '%Y-%m-%d').date()
        dates.append(d)
        vrps.append(int(v))



# RPKI growth
plt.plot_date(dates, vrps, '-', color = 'tab:blue', label = 'VRPs')
plt.xlabel('Date')
plt.ylabel('# of VRPs')
plt.legend()
plt.subplots_adjust(left = 0.18)
plt.savefig('./figures/rpki-deployment.png')

# shift dates back to correct spacing
dates = []
current = date(2011, 1, 20)
while current <= date(2020, 2, 29):
    dates.append(current)
    current += timedelta(days = 2)


# CDF of Attacks
plt.clf()

#attack_stats = { 2: 202274, 3: 4410, 4: 868, 5: 25, 6: 12, 7: 2, 8: 3, 9: 4, 10: 5, 11: 9, 12: 23, 13: 25, 14: 60, 15: 28, 16: 56, 17: 17, 18: 5, 19: 5, 20: 1, 21: 2, 22: 3, 24: 1, 25: 3 }
attack_stats = { 3: 4410, 4: 868, 5: 25, 6: 12, 7: 2, 8: 3, 9: 4, 10: 5, 11: 9, 12: 23, 13: 25, 14: 60, 15: 28, 16: 56, 17: 17, 18: 5, 19: 5, 20: 1, 21: 2, 22: 3, 24: 1, 25: 3 }
total_attacks = sum(attack_stats.values())

actors = [ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 25]
actor_percs = []
for i, num_attacks in enumerate(attack_stats.values()):
    if i == 0:
        actor_percs.append(num_attacks / total_attacks)
    else:
        actor_percs.append((num_attacks / total_attacks) + actor_percs[i - 1])

ax1 = plt.subplot2grid((1, 1), (0, 0))
ax1.set_xlabel('Number of Actors')
ax1.set_ylabel('')
ax1.set_xticks(list(range(3, 26)))
for label in ax1.xaxis.get_ticklabels():
    label.set_rotation(90)
plt.plot(actors, actor_percs, '-')
plt.savefig('./figures/attacks-cdf.png')

# number of prefixes vs number of isolated
plt.clf()
fig, ax1 = plt.subplots()
ax1.set_ylabel('# of Prefixes')
ax1.set_xlabel('Date')
ax1.set_ylim([0, max(prefixes) + 50000])
ln1 = ax1.plot_date(dates, prefixes, '-', color = 'tab:blue', label = 'Prefixes')
ax1.ticklabel_format(axis = 'y', useOffset = False, style = 'plain')

ax2 = ax1.twinx()
ax2.set_ylabel('# of Isolated Attacks')
ln2 = ax2.plot_date(dates, isolated_attacks, '-', color = 'tab:red', label = 'Isolated Attacks')
ax2.ticklabel_format(axis = 'y', useOffset = False, style = 'plain')

lns = ln1 + ln2
labels = [l.get_label() for l in lns]
plt.legend(lns, labels, loc = 'upper left')
plt.title('')
plt.subplots_adjust(left= 0.15, right = 0.85)
plt.savefig('./figures/isolated-and-unique-prefixes.png')

# number of prefixes vs number of distributed
plt.clf()
fig, ax1 = plt.subplots()
ax1.set_ylabel('# of Prefixes')
ax1.set_xlabel('Date')
ax1.set_ylim([0, max(prefixes) + 50000])
ln1 = ax1.plot_date(dates, prefixes, '-', color = 'tab:blue', label = 'Prefixes')
ax1.ticklabel_format(axis = 'y', useOffset = False, style = 'plain')

ax2 = ax1.twinx()
ax2.set_ylabel('# of Distributed Attacks')
ln2 = ax2.plot_date(dates, distributed_attacks, '-', color = 'tab:red', label = 'Distributed Attacks')
ax2.ticklabel_format(axis = 'y', useOffset = False, style = 'plain')

lns = ln1 + ln2
labels = [l.get_label() for l in lns]
plt.legend(lns, labels, loc = 'upper left')
plt.title('')
plt.subplots_adjust(left= 0.15, right = 0.85)
plt.savefig('./figures/distributed-and-unique-prefixes.png')

# percentage of isolated attacks over total prefix count
plt.clf()
fig, ax1 = plt.subplots()
ax1.set_ylabel('# of Prefixes')
ax1.set_xlabel('Date')
ax1.set_ylim([0, max(prefixes) + 50000])
ln1 = ax1.plot_date(dates, prefixes, '-', color = 'tab:blue', label = 'Prefixes')
ax1.ticklabel_format(axis = 'y', useOffset = False, style = 'plain')

ax2 = ax1.twinx()
ax2.set_ylabel('% of Isolated Attacks')
ln2 = ax2.plot_date(dates, isolated_percs, '-', color = 'tab:red', label = 'Isolated Attacks')
ax2.ticklabel_format(axis = 'y', useOffset = False, style = 'plain')

lns = ln1 + ln2
labels = [l.get_label() for l in lns]
plt.legend(lns, labels, loc = 'upper left')
plt.title('')
plt.subplots_adjust(left= 0.15, right = 0.85)
plt.savefig('./figures/isolated-percs-and-unique-prefixes.png')

# percentage of distributed attacks over total prefix count
plt.clf()
fig, ax1 = plt.subplots()
ax1.set_ylabel('# of Prefixes')
ax1.set_xlabel('Date')
ax1.set_ylim([0, max(prefixes) + 50000])
ln1 = ax1.plot_date(dates, prefixes, '-', color = 'tab:blue', label = 'Prefixes')
ax1.ticklabel_format(axis = 'y', useOffset = False, style = 'plain')

ax2 = ax1.twinx()
ax2.set_ylabel('% of Distributed Attacks')
ln2 = ax2.plot_date(dates, distributed_percs, '-', color = 'tab:red', label = 'Distributed Attacks')
ax2.ticklabel_format(axis = 'y', useOffset = False, style = 'plain')

lns = ln1 + ln2
labels = [l.get_label() for l in lns]
plt.legend(lns, labels, loc = 'upper left')
plt.title('')
plt.subplots_adjust(left= 0.15, right = 0.85)
plt.savefig('./figures/distributed-percs-and-unique-prefixes.png')
