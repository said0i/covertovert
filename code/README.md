# Covert Storage Channel that exploits Protocol Field Manipulation using Stratum field in NTP ---  [Code: CSC-PSV-NTP-STR]

  





## Project Overview
This project focuses on the **Covert Storage Channel** concept and implements a covert communication channel by manipulating the Stratum field in **NTP (Network Time Protocol)**. The goal is to demonstrate how protocol field manipulation can establish a hidden communication channel.

### Why Are We Doing This?
The primary motivation behind this project is to explore how unused or rarely scrutinized fields in network protocols can be leveraged for covert communication. Such studies have practical applications in cybersecurity, where understanding covert channels can help in detecting and mitigating potential data exfiltration methods. Additionally, this project serves as a proof of concept to showcase how subtle protocol field manipulations can bypass traditional detection mechanisms while still maintaining the original functionality of the protocol.

#### Why Doesn’t Modifying the Stratum Field Cause Issues?
The Stratum field in NTP is primarily used to indicate the quality or distance of the time source from the reference clock. In most practical scenarios, small changes in the Stratum field do not disrupt network operations, as the primary function of NTP (time synchronization) remains intact. By carefully choosing the range of values (e.g., 0-16), this project ensures that the manipulated values are within the acceptable bounds defined by the protocol, thereby minimizing any functional impact on the network. 

### Terminology
- **NTP (Network Time Protocol):**
  - NTP is a protocol used to synchronize the clocks of devices over a network. It ensures accurate timekeeping across systems by communicating with reference time servers. NTP operates on the UDP transport protocol and uses specific fields, like Stratum, to indicate the quality and accuracy of the time source.

- **Stratum Field:**
  - The Stratum field is part of the NTP protocol, indicating the distance (or "stratum") of the device from the reference clock. It is an 8-bit field where lower values represent higher accuracy clocks.

- **Covert Channel:**
  - A covert channel is a method of transmitting information using channels not intended for communication. It exploits unconventional means, such as protocol field manipulation, to secretly send data.

- **Protocol Field Manipulation:**
  - This involves altering specific fields in network protocol headers (like the Stratum field in NTP) to encode information, enabling data transmission in a way that bypasses conventional detection mechanisms.

### Working Principle
- **Stratum Field Manipulation:**
  - `0`: The Stratum field value is less than 8.
  - `1`: The Stratum field value is between 8 and 16.
- Messages are encoded in binary format through the manipulation of the Stratum field and transmitted.

## Installation and Usage Instructions

1. **Requirements:**
   - Python 3.10.12
   - Scapy library

2. **Installation:**
   ```bash
   pip install scapy
   ```

3. **Usage:**
   - **Receiving:**
     ```bash
     make receiver
     ```
   - **Sending:**
     ```bash
     make send
     ```
   - **Comparing Logs:**
     ```bash
     make compare
     ```

## Parameter Descriptions
| Parameter        | Description                                | Limitations          |
|------------------|--------------------------------------------|----------------------|
| `seperator_val`  | The threshold for separating Stratum values| Should be between 8-16 |
| `target_ip`      | Target IP address                          | Must be a valid IP address |
| `port`           | UDP port (default: 123)                    | 1-65535              |
| `log_file_name`  | The name of the log file for messages      | Any valid file name   |

## Limitations and Constraints
This implementation has the following limitations:

1. **Stratum Field Value Range:**
   - The Stratum field can only take values between 0 and 16. Values outside this range would violate the NTP protocol and could cause compatibility issues with other devices.

4. **Seperator Value (`seperator_val`):**
   - This parameter separates the Stratum field into two distinct ranges (e.g., 0-8 for `0` and 8-16 for `1`). Using extreme values outside this range could compromise the binary encoding and decoding process.

## Covert Channel Capacity
The capacity of the covert channel is calculated as follows:

1. **Binary Message Length:** 128 bits (16 characters).
2. **Time Measurement for Start and End:**
   - **Elapsed Time:** 3.14 seconds.
3. **Capacity Calculation:**
   ```
   Capacity (bps) = 128 / 3.14
   ```
4. **Result:** In a sample run, the capacity was measured as **41 bps**.

## Results and Evaluation
This project demonstrates an effective method for covert communication in scenarios with low bandwidth requirements. Optimization of timing and Stratum field manipulations can further increase channel capacity.

## Project Structure
- `MyCovertChannel.py`: Main application file.
- `CovertChannelBase.py`: Base class providing common functionalities.
- `config.json`: Configuration file storing parameters.