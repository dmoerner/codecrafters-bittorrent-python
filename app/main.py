import json
import sys

import hashlib

# import bencodepy - available if you need it!
# import requests - available if you need it!

def decode_string(bencoded_value):
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Not a string")
    length_string = int(bencoded_value[:first_colon_index])
    decoded_string = bencoded_value[first_colon_index+1:first_colon_index+1+length_string]
    bencoded_remainder = bencoded_value[first_colon_index+1+length_string:]
    return decoded_string, bencoded_remainder

def decode_int(bencoded_value):
    if chr(bencoded_value[0]) != 'i':
        raise ValueError("Not an integer")
    end_int = bencoded_value.find(b"e")
    if end_int == -1:
        raise ValueError("Not an integer")
    decoded_int = int(bencoded_value[1:end_int])
    bencoded_remainder = bencoded_value[end_int+1:]
    return decoded_int, bencoded_remainder

def decode_list(bencoded_value):
    if chr(bencoded_value[0]) != 'l':
        raise ValueError("Not a list")
    bencoded_remainder = bencoded_value[1:]
    decoded_list = []
    while chr(bencoded_remainder[0]) != 'e':
        decoded_value, bencoded_remainder = decode_bencode(bencoded_remainder)
        decoded_list.append(decoded_value)
    return decoded_list, bencoded_remainder[1:]

def decode_dict(bencoded_value):
    if chr(bencoded_value[0]) != 'd':
        raise ValueError("Not a dict")
    bencoded_remainder = bencoded_value[1:]
    decoded_dict = {}
    while chr(bencoded_remainder[0]) != 'e':
        decoded_key, bencoded_remainder = decode_string(bencoded_remainder)
        decoded_value, bencoded_remainder = decode_bencode(bencoded_remainder)
        decoded_dict[decoded_key.decode()] = decoded_value
    return decoded_dict, bencoded_remainder[1:]

def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        return decode_string(bencoded_value)
    elif chr(bencoded_value[0]) == 'i':
        return decode_int(bencoded_value)
    elif chr(bencoded_value[0]) == 'l':
        return decode_list(bencoded_value)
    elif chr(bencoded_value[0]) == 'd':
        return decode_dict(bencoded_value)
    else:
        raise NotImplementedError(f"We only support strings, integers, lists, and dicts.")

def bencode_string(unencoded_value):
    length = len(unencoded_value)
    return (str(length) + ":" + unencoded_value).encode()

def bencode_bytes(unencoded_value):
    length = len(unencoded_value)
    return str(length).encode() + b':' + unencoded_value

def bencode_int(unencoded_value):
    return ("i" + str(unencoded_value) + "e").encode()

def bencode_list(unencoded_value):
    result = b'l'
    for i in unencoded_value:
        result += bencode(i)
    return result + b'e'

def bencode_dict(unencoded_value):
    result = b'd'
    for k in unencoded_value:
        result += bencode(k) + bencode(unencoded_value[k])
    return result + b'e'

def bencode(unencoded_value):
    if isinstance(unencoded_value, str):
        return bencode_string(unencoded_value)
    elif isinstance(unencoded_value, bytes):
        return bencode_bytes(unencoded_value)
    elif isinstance(unencoded_value, int):
        return bencode_int(unencoded_value)
    elif isinstance(unencoded_value, list):
        return bencode_list(unencoded_value)
    elif isinstance(unencoded_value, dict):
        return bencode_dict(unencoded_value)
    else:
        raise ValueError("Can only bencode strings, ints, lists, or dicts.")

# json.dumps() can't handle bytes, but bencoded "strings" need to be
# bytestrings since they might contain non utf-8 characters.
#
# Let's convert them to strings for printing to the console.
def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()

    raise TypeError(f"Type not serializable: {type(data)}")


def main():
    command = sys.argv[1]

    # You can use print statements as follows for debugging, they'll be visible when running tests.
    #print("Logs from your program will appear here!")

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # Uncomment this block to pass the first stage
        decoded_value, remainder = decode_bencode(bencoded_value)

        if remainder:
            raise ValueError("Undecoded remainder.")

        print(json.dumps(decoded_value, default=bytes_to_str))

    elif command == "info":
        if len(sys.argv) != 3:
            raise NotImplementedError(f"Usage: {sys.argv[0]} info filename")
        with open(sys.argv[2], "rb") as f:
            bencoded_content = f.read()
            decoded_value, remainder = decode_bencode(bencoded_content)

            if remainder:
                raise ValueError("Undecoded remainder.")

            print("Tracker URL:", decoded_value["announce"].decode())
            print("Length:", decoded_value["info"]["length"])

            info_hash = hashlib.sha1(bencode(decoded_value["info"])).hexdigest()
            print("Info Hash:", info_hash)


    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
