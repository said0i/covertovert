from CovertChannelBase import CovertChannelBase
import random
from scapy.all import IP, UDP, sniff, NTP
import time

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()

    def encode_stratum(self, bit,seperator):
        """
        code the binary bit to Stratum field of NTP packet
        0 -> Stratum is less than 8  --- example: 0 -> Stratum = 5
        1 -> Stratum is between 8 and 16 --- example: 1 -> Stratum = 10  
        """
        return random.randrange(seperator) if bit == '0' else random.randrange(seperator, 16)

    def decode_stratum(self, stratum,seperator):
        # Solve the Stratum field of NTP packet to binary bit
        return '0' if stratum < seperator else '1'

    def send(self, seperator_val, target_ip, port, log_file_name):
        # Create a random message and convert it to binary then send it using Stratum field in NTP.
        # Create a binary message with logging 
        #binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        binary_message = self.generate_random_binary_message_with_logging(log_file_name,min_length=16,max_length=16)

        #print(f"Binary message: {binary_message}")
        

        for i,bit in enumerate(binary_message):
            # encode the bit to Stratum field
            stratum_value = self.encode_stratum(bit,seperator_val)
            '''
            # Create NTP packet with Stratum field
            ntp_payload = (
                b'\x1b'  # Leap Indicator (LI), Version, Mode
                + bytes([value])  # Stratum field (8 bits)
                + b'\x00' * 47  # Padding for rest of the NTP packet
            )
            
            # Wrap in UDP and IP layers
            packet = IP(dst=self.target_ip) / UDP(sport=123, dport=123) / Raw(load=ntp_payload)
            
            # Send packet
            send(packet, verbose=False)
            print(f"[*] Sent packet with Stratum value: {value}")
            '''
            # Create the NTP packet
            ntp_packet = (
                IP(dst=target_ip) /
                UDP(sport=port, dport=port) /
                NTP(stratum=stratum_value)
            )

            if i == 0:
                #start timer
                start_time = time.time()
            # Send the packet
            CovertChannelBase.send(self,ntp_packet)
            #self.sleep_random_time_ms(5, 15)  # Wait for a random time between 5 and 15 ms
        #stop timer
        end_time = time.time()
        passed_time = end_time - start_time
        print(f"Message sent successfully. Time elapsed: {passed_time} seconds, bitrate: {len(binary_message) / passed_time} bits/second")

    def receive(self, port, log_file_name,seperator_val):
        # Listen to the incoming NTP packets, decode the information in the Stratum field, and log the original message.
        self.char_bits = 0
        self.received_chars = 0
        self.decoded_message = ""
        self.last_char = ' '
        def packet_callback(packet):
            if packet.haslayer(NTP):
                # Get the Stratum field value from the NTP packet
                stratum_value = packet[NTP].stratum
                # Decode to binary 
                self.received_binary_message += self.decode_stratum(stratum_value,seperator_val)
                self.char_bits += 1
                print(f"Received bit: {self.decode_stratum(stratum_value,seperator_val)}")
        def stop_sniffing(packet):
            if self.char_bits == 8:
                self.last_char = self.convert_eight_bits_to_character(self.received_binary_message[self.received_chars * 8:self.received_chars * 8 + 8])
                self.decoded_message += self.last_char
                self.received_chars += 1
                self.char_bits = 0
                print(f"Received character: {self.last_char},received_chars: {self.received_chars}")
                if self.last_char == '.':
                    return True
        
        print("Receiving the message...")
        self.received_binary_message = ""
        
        # Belirtilen sayıda paketi dinle
        sniff(filter=f"udp port {port}", prn=packet_callback, stop_filter=stop_sniffing)

        # Binary mesajı orijinal metne çevir

        # Mesajı logla
        self.log_message(self.decoded_message, log_file_name)
        print(f"Alınan mesaj: {self.decoded_message}")




'''
from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, log_file_name, parameter1, parameter2):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        # Code to send the binary_message to the receiver container
        # For example, writing to a file or using a network socket
        with open(parameter1, 'w') as f:
            f.write(binary_message)
        
    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        # Code to receive the message from the sender container
        # For example, reading from a file or using a network socket
        with open(parameter1, 'r') as f:
            received_message = f.read()
        decoded_message = self.decode_binary_message(received_message)
        self.log_message(decoded_message, log_file_name)
        # - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        # - After the implementation, please rewrite this comment part to explain your code basically.
        self.log_message("", log_file_name)

'''