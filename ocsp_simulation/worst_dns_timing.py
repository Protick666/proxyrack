import pydig
import pycurl

def get_A_resolution_time_from_trace(trace):
    for element in trace[::-1]:
        try:
            if "A " in element:
                # milliseconds
                return int(element.split(" ")[-2])
        except:
            pass
    return None

def get_dns_timing(website):
    SAMPLE_PER_WEBSITE = 3

    resolution_time_list = []

    resolver = pydig.Resolver(
        additional_args=[
            '+trace',
        ]
    )
    for i in range(SAMPLE_PER_WEBSITE):
        try:
            trace_result = resolver.query(website, 'A')
            a_record_resolution_time_from_trace = get_A_resolution_time_from_trace(trace_result)
            if a_record_resolution_time_from_trace:
                resolution_time_list.append(a_record_resolution_time_from_trace)
        except:
            pass

    print("Done with dns: {}".format(website))
    return website, resolution_time_list

def load_qnames():
    import json

    # return ['google.com', 'facebook.com', 'youtube.com']

    filename = 'data/q_names.json'

    try:
        with open(filename, 'r') as f:
            import json
            q_names = json.load(f)
            return q_names
    except Exception:
        return []


if __name__ == '__main__':

    qnames = load_qnames()


    qname_to_response_time = {}

    from multiprocessing import Pool

    with Pool() as pool:
        for result in pool.imap_unordered(get_dns_timing, qnames):
            domain, resolution_time_list = result
            qname_to_response_time[domain] = resolution_time_list

    import json
    with open("data/qname_worst_to_response_time_list.json", "w") as ouf:
        json.dump(qname_to_response_time, fp=ouf)
