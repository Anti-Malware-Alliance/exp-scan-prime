import os.path
import sys

import pyarrow.csv as pv
import pyarrow.parquet as pq


def convert_file(file_name):
    table = pv.read_csv(file_name)
    pq.write_table(table, file_name.replace("csv", "parquet"))


if __name__ == "__main__":

    args = sys.argv

    if len(args) != 2:
        print("SCRIPT REQUIRES 1 ARGUMENT")
        print(args)
        sys.exit()

    file_name = args[1]
    if not os.path.isfile(file_name):
        print("ENSURE FILE NAME GIVEN IS CORRECT")
        sys.exit()

    convert_file(file_name)
