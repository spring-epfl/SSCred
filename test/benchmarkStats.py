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

    pfmt = "{:<30} {:<30} {:<30} {:<30}"

    title = pfmt.format('FUNCTION', 'MEAN', 'MEDIAN', 'STDDEV')
    print(title)
    print('-' * len(title))

    for k, v in process_times.items():
        mean = statistics.mean(v)
        median = statistics.median(v)
        stdev = statistics.pstdev(v)

        print(pfmt.format(k, mean, median, stdev))

