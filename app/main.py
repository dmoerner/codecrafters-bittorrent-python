import json
import sys

# import bencodepy - available if you need it!
# import requests - available if you need it!

# Going to try this with a global variable
bencoded_value = ''

# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"

def decode_bencode():
    global bencoded_value
    if chr(bencoded_value[0]).isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        length_string = int(bencoded_value[:first_colon_index])
        decoded_string = bencoded_value[first_colon_index+1:first_colon_index+1+length_string]
        bencoded_value = bencoded_value[first_colon_index+1+length_string:]
        return decoded_string
    elif (chr(bencoded_value[0]) == 'i'):
        end_int = bencoded_value.find(b"e")
        decoded_string = bencoded_value[1:end_int]
        bencoded_remainder = bencoded_value[end_int+1:]
        if not decoded_string:
            raise ValueError("Expected integer, but found null value.")
        try:
            decoded_int = int(decoded_string)
        except ValueError:
            raise ValueError("Expected integer, but input is not an integer.")
        bencoded_value = bencoded_value[end_int+1:]
        return decoded_int
    elif (chr(bencoded_value[0]) == 'l'):
        bencoded_value = bencoded_value[1:]
        decoded_list=[]
        while bencoded_value:
            next_value = decode_bencode()
            decoded_list.append(next_value)
            if chr(bencoded_value[0]) == 'e':
                bencoded_value = bencoded_value[1:]
                return decoded_list
    else:
        raise NotImplementedError(f"We only support strings, integers, and lists.")


def main():
    command = sys.argv[1]

    # You can use print statements as follows for debugging, they'll be visible when running tests.
    #print("Logs from your program will appear here!")

    if command == "decode":
        global bencoded_value
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        # Uncomment this block to pass the first stage
        print(json.dumps(decode_bencode(), default=bytes_to_str))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
