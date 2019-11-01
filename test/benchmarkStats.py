#!/usr/bin/env python3

import json
import statistics
import sys

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.stderr.write('Usage: {} <file.json>\n'.format(sys.argv[0]))
        sys.exit(1)

    file_name = sys.argv[1]

    with open(file_name, 'r') as fd:
        content = fd.read()

    process_times = json.loads(content)

    pfmt_title = "{:<30} {:>20} {:>20} {:>20}"
    pfmt = "{:<30} {:20.3f} {:20.3f} {:20.3f}"

    title = pfmt_title.format('FUNCTION', 'MEAN', 'MEDIAN', 'STDDEV')
    print(title)
    print('-' * len(title))

    ms_scale = 1000

    for k, v in process_times.items():
        mean = ms_scale * statistics.mean(v)
        median = ms_scale * statistics.median(v)
        stdev = ms_scale * statistics.pstdev(v)

        print(pfmt.format(k, mean, median, stdev))

