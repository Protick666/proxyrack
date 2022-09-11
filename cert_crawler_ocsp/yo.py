import os, shutil
import random

RESULTS_EXTN = ".apk"

ACTUAL_LOG_PATH = '/net/data/cert-pinning/raw_apps/android/topFree_1k_from10k'
DEST = '/home/protick/random_1_k'

def allowed(f, allowed_prefixes):
    for e in allowed_prefixes:
        if e in f:
            return True
    return False

def get_files_from_path(path, extension, check=False, allowed_prefixes=None):
    retset = set()
    for f in os.listdir(path):

        if f.endswith(extension):
            if check:
                if not allowed(f, allowed_prefixes):
                    continue
            retset.add(path + "/" + f) # Need to track path as well
    return retset


solo_data = {}
path_to_logs = ACTUAL_LOG_PATH
tls_res_files = set()
for path in [path_to_logs]:
    tls_res_files.update(get_files_from_path(path, RESULTS_EXTN))

all_prefixes = set()
for file in tls_res_files:
    end_part = file.split("/")[-1]
    prefix = end_part.split("-")[0]
    all_prefixes.add(prefix)

all_prefixes = list(all_prefixes)

allowed_prefixes = random.sample(all_prefixes, 100)

tls_res_files = set()
for path in [path_to_logs]:
    tls_res_files.update(get_files_from_path(path, RESULTS_EXTN, check=True, allowed_prefixes=allowed_prefixes))

for file in tls_res_files:
    shutil.copy(file, DEST)

