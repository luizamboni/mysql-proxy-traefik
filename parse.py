import sys
import re
import base64



is_init_pachage = re.compile('^\d{,2}:\d{,2}:\d{,2}.')
is_data_pachage = re.compile('^\dx\d{,4}:\t*(d{4})')

combine_whitespaces = re.compile(r"\s+")


def find_index(L, obj):
  try:
    return L.index(obj)
  except ValueError:
    return -1


def from_hex_to_ascii(string):
    return string.decode("hex")
 

def from_hex_to_int(string):
    return str(int(string,16))

def main():

  buffer_data = ""

  # control if need process current package
  current_line = None;

  for line in sys.stdin:
    # if is first line 
    if is_init_pachage.match(line):
        current_line = line;
        
        # every new line clear buffer_data
        if len(buffer_data) > 0:

            hex_payload = combine_whitespaces.sub('',buffer_data)
            ascii_string = from_hex_to_ascii(hex_payload)
    
            # ip_len = str(int(hex_payload[3:3], 16))
            ip_len = int(hex_payload[4:8],16)
            # sys.stdout.write("ip len: " + ip_len + "\n")

            hex_payload_size = combine_whitespaces.sub('',buffer_data[:14])


            sys.stdout.write("payload len: " + str(len(ascii_string)) + "\n")
            sys.stdout.write('payload: ' +  ascii_string +  "\n")
            buffer_data = ""

        
        sys.stdout.write("\n")
        tokens = line.split(' ')

        addrs = {
            "length": "",
            "seq": {
                "first": "",
                "last": "",
            },
            "ack": ""
        }

        # length
        if find_index(tokens,'length') != -1:
            idx = find_index(tokens, 'length')
            idx_value = idx + 1

            if tokens[idx_value].strip() == "0":
                current_line = None;
                continue;

            addrs["length"] = tokens[idx_value]

        # seq numbers
        if find_index(tokens,'seq') != -1:
            idx = find_index(tokens,'seq')

            seq_numbers = []
            for number in tokens[idx +1 ].rstrip(',').split(':'):
                seq_numbers.append(number)
            
            if len(seq_numbers) > 1:
                addrs["seq"]["first"] = seq_numbers[0]
                addrs["seq"]["last"] = seq_numbers[1]
            else:
                addrs["seq"]["first"] = seq_numbers[0]

        # ack
        if find_index(tokens,'ack') != -1:
            idx = find_index(tokens, 'ack')
            addrs["ack"] = tokens[idx +1 ].rstrip(',')
        
        

        # sys.stdout.write( ' '.join(tokens[7:]) + '\n')

        sys.stdout.write( line )
    else:
        if current_line != None:
            tokens = combine_whitespaces.sub(' ', line[10:49]).strip()
            buffer_data += tokens


if __name__ == "__main__":
    main()
