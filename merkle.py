import binarytree as bt
from hashlib import sha256
import threading
from fastecdsa import curve
from itertools import combinations

def build_tree(leafs, tree):
    if len(leafs) == 1: # root
        tree.append(leafs[0])
        return

    next_level = []
    i = 0
    while i < len(leafs):
        next_level.append(leaf_hash(leafs[i], leafs[i+1]))
        i += 2

    build_tree(next_level, tree)
    for leaf in leafs:
        tree.append(leaf)

def threaded_hashes(input):
    input_len = len(input)
    thread_list = []
    output = []
    for i in range(input_len):
        thread = threading.Thread(target=thread_hash, args=(input[i], i, output))
        thread_list.append(thread)
        thread.start()

    for thread in thread_list:
        thread.join()

    return output

def thread_hash(input, index, output):
    h = sha256()
    h.update((str(input)).encode())
    h = h.hexdigest()
    output.append((index, h))

def leaf_hash(input1, input2):
    h = sha256()
    h.update(input1.encode())
    h.update(input2.encode())

    return h.hexdigest()

def sort_hashes(input):
    if len(input) > 1:
        mid = len(input)//2
        left = input[:mid]
        right = input[mid:]

        sort_hashes(left)
        sort_hashes(right)

        i, j, k = 0, 0, 0

        while i < len(left) and j < len(right):
            if right[j][0] > left[i][0]:
                input[k] = left[i]
                i += 1
            else:
                input[k] = right[j]
                j += 1
            k += 1

        while i < len(left):
            input[k] = left[i]
            i += 1
            k += 1

        while j < len(right):
            input[k] = right[j]
            j += 1
            k += 1

def clear_hash_list(input):
    out = []
    for item in input:
        out.append(item[1])
    return out

def produce_proof(key, tree):
    h = sha256()
    h.update((str(key)).encode())
    key_hash = h.hexdigest()

    key_index = None
    total_nodes = len(tree)
    i = -1

    while i > (total_nodes * (-1)):
        if tree[i] == key_hash:
            key_index = total_nodes + i # index = len(tree) - reverse position
            break
        i -= 1

    proof = []

    tree_search(key_index, tree, proof)

    return proof

def tree_search(index, tree, output):
    if index == 0:
        return

    if index is None:
        return

    parent_index = (index - 1)//2

    first_child = tree[2 * parent_index + 1]
    second_child = tree[2 * parent_index + 2]

    output.append(first_child)
    output.append(second_child)

    tree_search(parent_index, tree, output)

def verify(root, key, proof):
    h = sha256()
    h.update((str(key)).encode())
    hash_value = h.hexdigest()

    proof_len = len(proof)
    i = 0
    while i < proof_len:
        if hash_value == proof[i] or hash_value == proof[i+1]:
            hash_value = leaf_hash(proof[i], proof[i + 1])
            i += 2
            # the last hash calculated will be the proof root
        else:
            return False

    if root == hash_value:
        return True
    else:
        return False

def ispoweroftwo(value):
    if value > 0 and (value & value-1) == 0:
        return True
    else:
        return False

def adjust_leafs_for_binary_tree(entry_list):
    if ispoweroftwo(len(entry_list)):
        return True

    size = len(entry_list)
    i = 1

    while size > 2**i:
        i += 1

    k = 2**i - size

    last_value = entry_list[-1]

    for j in range(k):
        entry_list.append(last_value)

    if ispoweroftwo(len(entry_list)):
        return True
    else:
        return False

