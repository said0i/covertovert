from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, sniff, NTP

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()

    def encode_stratum(self, bit):
        """
        code the binary bit to Stratum field of NTP packet
        0 -> Stratum = 5  --- example: 0 -> Stratum = 5
        1 -> Stratum = 10 --- example: 1 -> Stratum = 10  
        """
        return 5 if bit == '0' else 10

    def decode_stratum(self, stratum):
        # Solve the Stratum field of NTP packet to binary bit
        return '0' if stratum == 5 else '1'

    def send(self, log_file_name, target_ip, interface):
        # Rastgele bir mesaj oluşturur, binary formata çevirir ve NTP paketlerinin Stratum alanı kullanılarak gönderir.
        # Rastgele bir binary mesaj oluştur ve logla
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        print(f"Gönderilecek binary mesaj: {binary_message}")

        for bit in binary_message:
            # Binary bit'i Stratum alanına kodla
            stratum_value = self.encode_stratum(bit)

            # NTP paketi oluştur
            ntp_packet = (
                IP(dst=target_ip) /
                UDP(sport=12345, dport=123) /
                NTP(stratum=stratum_value)
            )

            # Paketi gönder
            self.send(ntp_packet, interface=interface)
            self.sleep_random_time_ms(5, 15)  # Her paket arasında rastgele bekle

        print("Mesaj gönderimi tamamlandı.")

    def receive(self, interface, packet_count, log_file_name):
        # Gelen NTP paketlerini dinler, Stratum alanındaki bilgiyi çözer ve orijinal mesajı loglar.

        def packet_callback(packet):
            if packet.haslayer(NTP):
                # Stratum alanını al
                stratum_value = packet[NTP].stratum
                # Binary olarak çöz
                self.received_binary_message += self.decode_stratum(stratum_value)

        print("Mesaj alımı başlatılıyor...")
        self.received_binary_message = ""
        
        # Belirtilen sayıda paketi dinle
        sniff(filter="udp port 123", iface=interface, prn=packet_callback, count=packet_count)

        # Binary mesajı orijinal metne çevir
        decoded_message = ''.join(
            self.convert_eight_bits_to_character(self.received_binary_message[i:i + 8])
            for i in range(0, len(self.received_binary_message), 8)
        )

        # Mesajı logla
        self.log_message(decoded_message, log_file_name)
        print(f"Alınan mesaj: {decoded_message}")




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