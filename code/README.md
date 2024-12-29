# Replace with Your Covert Channel Name

Explain your study in detail as you share your work with the community in a public repository. Anyone should understand your project when read it without having a previous information about the homework.


# README.md

## Project Overview
This project focuses on the **Covert Storage Channel** concept and implements a covert communication channel by manipulating the Stratum field in **NTP (Network Time Protocol)**. This approach establishes a hidden communication channel using protocol field manipulation.

### Working Principle
- **Stratum Field Manipulation:**
  - `0`: The Stratum field value is less than 8.
  - `1`: The Stratum field value is between 8 and 16.
- Messages are encoded in binary format through the manipulation of the Stratum field and transmitted.

## Installation and Usage Instructions

1. **Requirements:**
   - Python 3.x
   - Scapy library

2. **Installation:**
   ```bash
   pip install scapy
   ```

3. **Usage:**
   - **Sending:**
     ```bash
     python myCovertChannel.py send
     ```
   - **Receiving:**
     ```bash
     python myCovertChannel.py receive
     ```

## Parameter Descriptions
| Parameter        | Description                                | Limitations          |
|------------------|--------------------------------------------|----------------------|
| `seperator_val`  | The threshold for separating Stratum values| Should be between 8-16 |
| `target_ip`      | Target IP address                          | Must be a valid IP address |
| `port`           | UDP port (default: 123)                    | 1-65535              |
| `log_file_name`  | The name of the log file for messages      | Any valid file name   |

## Limitations and Constraints
- The Stratum field can only take values between 0 and 16.
- The maximum message length is limited to 128 bits.

## Covert Channel Capacity
The capacity of the covert channel is calculated as follows:

1. **Binary Message Length:** 128 bits (16 characters).
2. **Time Measurement for Start and End:**
   - **Elapsed Time:** X seconds.
3. **Capacity Calculation:**
   ```
   Capacity (bps) = 128 / X
   ```
4. **Result:** In a sample run, the capacity was measured as 20 bps.

## Results and Evaluation
This project demonstrates an effective method for covert communication in scenarios with low bandwidth requirements. Optimization of timing and Stratum field manipulations can further increase channel capacity.

## Project Structure
- `myCovertChannel.py`: Main application file.
- `CovertChannelBase.py`: Base class providing common functionalities.
- `config.json`: Configuration file storing parameters.

## License and Contributions
This project is intended for educational purposes. Contributions are welcome via pull requests or issue submissions.
