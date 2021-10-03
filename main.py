import numpy as np
import hashlib as h
import random
import pandas as pd
import time
from bisect import bisect_left
from pathlib import Path


def get_chains():
    global filename, m, t
    print('Mining chains...')
    all_chains = []
    if Path(filename).is_file():
        with open(filename) as f:
            chains = list(np.loadtxt(f, delimiter=",", skiprows=1, dtype=str))
    else:
        start_points = get_start_points(m)
        chains = []
        for start_point in start_points:
            (all_hashes, end_point) = hash_value_t_times(start_point)
            chains.append([start_point, end_point])
            all_chains.append([start_point, all_hashes])
        chains = sort_chains(chains)
        save_chains_to_csv(chains)
    print('Mining chains finished.')
    return all_chains, chains


def get_start_points(m):
    global ais_id, pin_length
    start_points = []
    m_random_numbers = random.sample(range(1000000), m)
    for i in m_random_numbers:
        start_points.append((ais_id + ('0' * (pin_length - len(str(i)))) + str(i)))
    return start_points


def hash_value_t_times(s):
    global t
    all_hashes = []
    for j in range(t - 1):
        s = h.sha256(s.encode()).hexdigest()
        all_hashes.append(s)
        s = reduce(s, j)
    s = h.sha256(s.encode()).hexdigest()
    all_hashes.append(s)
    return all_hashes, s


def reduce(s, t_iteration):
    global ais_id, rainbow
    s_int = abs((hash(s) + int(t_iteration if rainbow else 0)) % (10 ** 6))
    reduced_hash = str(s_int)
    return ais_id + reduced_hash


def get_bytes(hash):
    results = []
    remaining = int(hash, 16)
    while remaining > 0:
        results.append(remaining % 256)
        remaining //= 256
    return results


def sort_chains(chains):
    return sorted(chains, key=lambda x: x[1])


def save_chains_to_csv(chains):
    global filename
    df = pd.DataFrame(chains)
    df.columns = ['start_point', 'end_point']
    df.to_csv(filename, index=False)


def find_hash(password, chains_end_points, chains):
    global t
    s = password
    found_passwords = []
    for t_iteration in range(t):
        s = h.sha256(s.encode()).hexdigest()
        chain_index = binary_search(chains_end_points, s)
        if chain_index is not None:
            pt, t_found_iteration = find_plain_text_from_m(chains, h.sha256(password.encode()).hexdigest(), chain_index,
                                                           t)
            if pt is not None:
                if pt == password:
                    print('Password found on chain =', chain_index, ', T =', t_found_iteration, ' , PT:', pt)
                    found_passwords.append([pt, chain_index, t_found_iteration])
                else:
                    print('False alarm')
        s = reduce(s, t_iteration)
    if len(found_passwords) == 0:
        print('No password was found.')
    return found_passwords


def find_plain_text_from_m(chains, hash, chain_index, t):
    start_point = chains[chain_index][0]
    prev_s = start_point
    s = h.sha256(start_point.encode()).hexdigest()
    for t_iteration in range(t):
        if s == hash:
            return prev_s, t_iteration
        s = reduce(s, t_iteration)
        prev_s = s
        s = h.sha256(s.encode()).hexdigest()
    return None, None


def binary_search(chains_end_points, hash):
    i = bisect_left(chains_end_points, hash)
    if i != len(chains_end_points) and chains_end_points[i] == hash:
        return i
    return None


def find_duplicates(chains, details=False):
    end_points = [chain[1] for chain in chains]
    end_points = sorted(end_points)
    unique_end_points = dict()
    for i in end_points:
        if unique_end_points.get(i) is not None:
            unique_end_points[i] += 1
        else:
            unique_end_points[i] = 1
    print('Unique end-points:', len(unique_end_points))
    if details:
        print('Repeating end points:')
        for i in unique_end_points.keys():
            if unique_end_points[i] > 1:
                print('End point:', i, ' ---- Repeated:', unique_end_points[i])
    print()


def test(chains):
    global ais_id, pin_length, m, t, filename
    print('Starting testing...')
    number_of_test_cases = 1000
    test_passwords = random.sample(range(1000000), number_of_test_cases)
    successful_searches = 0
    all_time = 0
    for i in test_passwords:
        start_searching_time = time.time()
        password = str(i)
        password = ais_id + ('0' * (pin_length - len(str(password)))) + str(password)
        print('Password:', password)
        found_passwords = find_hash(password=password, chains_end_points=[chain[1] for chain in chains], chains=chains)
        if len(found_passwords) > 0:
            successful_searches += 1
        end_searching_time = time.time()
        print('Time taken for search (in seconds):', end_searching_time - start_searching_time)
        all_time += end_searching_time - start_searching_time
        print()
    average_time_of_searching = all_time / number_of_test_cases
    result = [
        'Successful searches: ' + str(successful_searches) + '/' + str(number_of_test_cases),
        'Success percent: ' + str(round(successful_searches / number_of_test_cases * 100, 2)),
        'Expectation (success probability): ' + str(((0.8 * m * t) / (10 ** 6)) * 100),
        'Average time of searching: ' + str(average_time_of_searching)
    ]
    with open('results_' + filename + '.txt', 'w') as f:
        for i in result:
            f.write(i)
            f.write('\n')
            print(i)


def run():
    global rainbow
    print('Mode:', ('Rainbow' if rainbow else 'Hellman'), '\n')
    all_hashes, chains = get_chains()
    find_duplicates(chains)
    test(chains)


m = 100
t = 10000
pin_length = 6
rainbow = True
ais_id = '93800'

filename = 'chains_' + ('rainbow_' if rainbow else 'hellman_') + str(m) + '_' + str(t) + '.csv'

run()
