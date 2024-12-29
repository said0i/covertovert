from CovertChannelBase import CovertChannelBase
import random
from scapy.all import IP, UDP, sniff, NTP
import time

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()

    def encode_stratum(self, bit,seperator):
        """
        Encodes a binary bit into the Stratum field of an NTP packet.
        - A '0' bit is encoded as a Stratum value less than the separator (e.g., Stratum = 5).
        - A '1' bit is encoded as a Stratum value between the separator and 16 (e.g., Stratum = 10).
        """
        return random.randrange(seperator) if bit == '0' else random.randrange(seperator, 16)

    def decode_stratum(self, stratum,seperator):
        """
        Decodes the Stratum field value back into a binary bit.
        - Returns '0' if the Stratum value is less than the separator.
        - Returns '1' if the Stratum value is greater than or equal to the separator.
        """
        return '0' if stratum < seperator else '1'

    def send(self, seperator_val, target_ip, port, log_file_name):
        """
        Sends a covert message by encoding binary bits into the Stratum field of NTP packets.
        - A random binary message is generated and logged for comparison.
        - Each bit of the message is encoded as a Stratum value and sent in a separate NTP packet.
        - The elapsed time for sending the message is calculated to determine the transmission bitrate.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name,min_length=16,max_length=16)
        

        for i,bit in enumerate(binary_message):
            # Encode the bit into a Stratum value
            stratum_value = self.encode_stratum(bit,seperator_val)
            
            # Create the NTP packet
            ntp_packet = (
                IP(dst=target_ip) /
                UDP(sport=port, dport=port) /
                NTP(stratum=stratum_value)
            )

            if i == 0:
                start_time = time.time() # Timer starts just before the first packet is sent.
            
            CovertChannelBase.send(self,ntp_packet) # Send the packet
       
        
        
        end_time = time.time()  # Timer stops after the last packet is sent.
        passed_time = end_time - start_time     # Calculate the elapsed time
        
        print(f"Message sent successfully. Time elapsed: {passed_time} seconds, bitrate: {len(binary_message) / passed_time} bits/second")

    def receive(self, port, log_file_name,seperator_val):
        """
        Receives and decodes a covert message from NTP packets.
        - Captures incoming NTP packets and decodes the binary bits from their Stratum fields.
        - Stops when the full message is decoded, signaled by a '.' character at the end.
        - Logs the decoded message for comparison.
        """

        self.char_bits = 0  # Initialize the character bits counter
        self.received_chars = 0  # Initialize the received characters counter
        self.decoded_message = ""  # Initialize the decoded message buffer
        self.last_char = ' '       # Initialize the last character buffer
        def packet_callback(packet):   
            
            """
            Processes each captured packet, extracts the Stratum value,
            and decodes it into a binary bit.
            """

            if packet.haslayer(NTP):
                # Get the Stratum field value from the NTP packet
                stratum_value = packet[NTP].stratum
                # Decode to binary 
                self.received_binary_message += self.decode_stratum(stratum_value,seperator_val)
                self.char_bits += 1
                print(f"Received bit: {self.decode_stratum(stratum_value,seperator_val)}")
        def stop_sniffing(packet):
            
            """
            Determines when to stop sniffing packets.
            - Stops after decoding a full character when the '.' character is received.
            """
            
            if self.char_bits == 8:
                self.last_char = self.convert_eight_bits_to_character(self.received_binary_message[self.received_chars * 8:self.received_chars * 8 + 8])
                self.decoded_message += self.last_char
                self.received_chars += 1
                self.char_bits = 0
                print(f"Received character: {self.last_char},received_chars: {self.received_chars}")
                if self.last_char == '.':
                    return True   # Stop sniffing when the '.' character is received
        
        print("Receiving the message...")
        self.received_binary_message = ""   # Initialize the received binary message buffer
        
        # Start sniffing packets
        sniff(filter=f"udp port {port}", prn=packet_callback, stop_filter=stop_sniffing)

        # Convert the received binary message to a string

        
        self.log_message(self.decoded_message, log_file_name)
        # Log the received message

        print(f"Received Message: {self.decoded_message}")




