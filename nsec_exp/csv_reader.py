import csv
import multiprocessing as mp
from csv import reader
counter = None

def chunks(lst, n):
    ans = []
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        ans.append(lst[i:i + n])
    return ans


from collections import defaultdict

parent_fp_to_serials = defaultdict(lambda : list())
serial_set = set()
leaf_fp_set = set()


global_counter = 0
total_chunks = 0
def process_chunk(chunk):
    global parent_fp_to_serials, serial_set, leaf_fp_set, global_counter, total_chunks

    for e in chunk:
        try:
            serial = e[-2]
            concat_fp = e[-3]
            parent_fp = concat_fp.split("+")[0].upper()
            leaf_fp = e[-4].upper()
            serial_set.add(serial)
            parent_fp_to_serials[parent_fp].append(serial)
            leaf_fp_set.add(leaf_fp)
        except:
            pass

    global_counter = global_counter + 1
    print("Done {}/{}".format(global_counter, total_chunks))


    # ctlog-url, cert-index, isPrecertificate, timestamp, not-before, not-after, leaf-fingerprint, "+" joined fingerprint of chains, serial number, all domains
if __name__ == '__main__':


    with open('/net/data/ctlogs-latest-crawl/certificates/argon2022.csv', 'r') as read_obj:
        csv_reader = reader(read_obj)

        all_rows = list(csv_reader)

        print("Done loading the file")

        chunks = chunks(all_rows, 10)

        total_chunks = len(chunks)

        from multiprocessing.dummy import Pool as ThreadPool

        pool = ThreadPool(50)
        results = pool.map(process_chunk, chunks)
        pool.close()
        pool.join()

        print("Done processing")
        a = 1

        leaf_fp_set = list(leaf_fp_set)
        serial_set = list(serial_set)

        a = 1


        ans_dict = {
            "leaf_fp_list": leaf_fp_set,
            "serial_list": serial_set,
            "parent_fp_to_serials": parent_fp_to_serials
        }

        import json
        with open("data/argon2022_result.json", "w") as ouf:
            json.dump(ans_dict, fp=ouf)

        print("Done Dumping")

