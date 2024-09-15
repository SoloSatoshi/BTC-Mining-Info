#This code was written by @BTC_Cracker (X) and donated to SoloSatoshi for his blog.  This code is NOT
#to be used for illegal or abuse purposes. It is NOT to be used for commercial purposes or changed. It is a learning tool only.
#I do not take responsibility for abuse.

#The code is most likely complete garbage.  Use it at your own risk. If you find a bug, fix it yourself.

#The "mining" features mine the last solved block. This is a PoC.  It isn't actually mining the latest block.

import requests
import time
import hashlib
import struct
import random
import argparse


# ANSI color codes
BLUE = '\033[1;34m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
MAGENTA = '\033[1;35m'
CYAN = '\033[1;36m'
RED = '\033[1;31m'
RESET = '\033[0m'

# URL for Blockstream API
BLOCKSTREAM_API_URL = "https://blockstream.info/api"

def get_block_info(block_hash):
    try:
        response = requests.get(f"{BLOCKSTREAM_API_URL}/block/{block_hash}")
        response.raise_for_status()
        block_data = response.json()

        block_height = block_data.get('height', 'N/A')
        prev_block_hash = block_data.get('previousblockhash', 'N/A')
        merkle_root = block_data.get('merkle_root', 'N/A')
        timestamp = block_data.get('timestamp', 'N/A')
        difficulty_target = block_data.get('bits', 'N/A')
        block_version = block_data.get('version', 'N/A')

        print("Block Height:", block_height)
        print("Previous Block Hash:", prev_block_hash)
        print("Merkle Root:", merkle_root)
        print("Timestamp:", time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp)) if timestamp != 'N/A' else 'N/A')
        print("Difficulty Target (Bits):", difficulty_target)
        print("Block Version:", block_version)

        # Calculate and print the target and leading zeros here
        target = bits_to_target(difficulty_target)
        leading_zeros = calculate_leading_zeros(target)
        print(f"Target (Difficulty): {target:064x}")
        print(f"Leading Zeros Required: {leading_zeros}")

        return {
            'block_height': block_height,
            'prev_block_hash': prev_block_hash,
            'merkle_root': merkle_root,
            'timestamp': timestamp,
            'difficulty_target': difficulty_target,
            'block_version': block_version
        }
    except requests.exceptions.RequestException as e:
        print("Error fetching data from the API:", e)
    except KeyError as e:
        print(f"Key error: {e}. This key might not exist in the block data.")
    except Exception as e:
        print("An unexpected error occurred:", e)

def get_latest_block_hash(retries=3, delay=5):
    for attempt in range(retries):
        try:
            response = requests.get(f"{BLOCKSTREAM_API_URL}/blocks/tip/hash")
            response.raise_for_status()
            latest_block_hash = response.text.strip()
            return latest_block_hash
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt < retries - 1:
                print(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                print("Max retries reached. Unable to fetch the latest block hash.")
                return None

def format_timestamp(timestamp):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp))

def get_block_data_from_blockchain_info(block_hash):
    url = f"https://blockchain.info/rawblock/{block_hash}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"Block with hash {block_hash} not found on blockchain.info.")
        else:
            print(f"HTTP error occurred: {e}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching block data: {e}")
    return None

def verifier_mode():
    latest_block_hash = get_latest_block_hash()

    if not latest_block_hash:
        print("Unable to proceed with verification due to failure in fetching the latest block hash.")
        return

    # Get the data of the latest (already solved) block
    current_block_data = get_block_data_from_blockchain_info(latest_block_hash)

    if not current_block_data:
        print("Unable to proceed with verification due to failure in fetching block data.")
        return

    print("Verifier Mode: Showing details of the last solved block.")
    print(f"{RED}Code by @BTC_Cracker for SoloSatoshi - Give me a follow or Comment on X{RESET}")
    print(f"Block Height: {current_block_data['height']}")
    print(f"Block Hash: {current_block_data['hash']}")
    print(f"Block Version: {CYAN}{current_block_data['ver']}{RESET}")
    print(f"Previous Block Hash: {BLUE}{current_block_data['prev_block']}{RESET}")
    print(f"Merkle Root: {GREEN}{current_block_data['mrkl_root']}{RESET}")
    print(f"Timestamp: {YELLOW}{current_block_data['time']}{RESET} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(current_block_data['time']))})")
    print(f"Difficulty Target (Bits): {MAGENTA}{current_block_data['bits']}{RESET}")
    print(f"Nonce: {RED}{current_block_data['nonce']}{RESET}")

    # Get previous block data and calculate time delta
    previous_block_data = get_block_data_from_blockchain_info(current_block_data['prev_block'])
    if previous_block_data:
        time_delta = current_block_data['time'] - previous_block_data['time']
        minutes, seconds = divmod(time_delta, 60)
        print(f"Time since last mined block: {minutes} minutes and {seconds} seconds")
    else:
        print("Unable to calculate time since previous block due to error in fetching previous block data.")

    # Create the block header
    block_header = create_block_header(
        current_block_data['ver'],
        current_block_data['prev_block'],
        current_block_data['mrkl_root'],
        current_block_data['time'],
        current_block_data['bits'],
        current_block_data['nonce']
    )

    # Color-code the block header hex
    header_hex = block_header.hex()
    colored_header = (
        f"{CYAN}{header_hex[:8]}{RESET}"
        f"{BLUE}{header_hex[8:72]}{RESET}"
        f"{GREEN}{header_hex[72:136]}{RESET}"
        f"{YELLOW}{header_hex[136:144]}{RESET}"
        f"{MAGENTA}{header_hex[144:152]}{RESET}"
        f"{RED}{header_hex[152:]}{RESET}"
    )
    print(f"\nBlock Header (hex): {colored_header}")

    # Perform hashing
    first_hash = hashlib.sha256(block_header).digest()
    final_hash = hashlib.sha256(first_hash).digest()

    print("\nStep-by-step Hashing:")
    print(f"First SHA-256 Hash:    {first_hash.hex()}")
    print(f"Final SHA-256d Hash:   {final_hash[::-1].hex()}")  # Reverse for big-endian display

    target = bits_to_target(current_block_data['bits'])
    if int.from_bytes(final_hash, 'little') < target:
        print("\nSuccess! The block hash meets the difficulty target.")
        print(f"{RED}Code by @BTC_Cracker for SoloSatoshi - Give me a follow or Comment on X{RESET}")
        print(f"Block hash: {final_hash[::-1].hex()}")
        print(f"Target:     {target:064x}")
    else:
        print("\nFailure! The block hash does not meet the difficulty target.")

def calculate_leading_zeros(target):
    target_hex = f"{target:064x}"  # Convert target to a 64-character hexadecimal string
    leading_zeros = 0

    # Count the number of leading zeros
    for char in target_hex:
        if char == '0':
            leading_zeros += 1
        else:
            break

    return leading_zeros

def create_block_header(version, prev_block_hash, merkle_root, timestamp, bits, nonce):
    version_bytes = struct.pack("<L", version)  # 4 bytes, little-endian
    prev_block_hash_bytes = bytes.fromhex(prev_block_hash)[::-1]  # 32 bytes, reversed byte order
    merkle_root_bytes = bytes.fromhex(merkle_root)[::-1]  # 32 bytes, reversed byte order
    timestamp_bytes = struct.pack("<L", timestamp)  # 4 bytes, little-endian
    bits_bytes = struct.pack("<L", bits)  # 4 bytes, little-endian
    nonce_bytes = struct.pack("<L", nonce)  # 4 bytes, little-endian

    block_header = (
        version_bytes +
        prev_block_hash_bytes +
        merkle_root_bytes +
        timestamp_bytes +
        bits_bytes +
        nonce_bytes
    )

    return block_header

def hash_block_header(block_header):
    hash1 = hashlib.sha256(block_header).digest()
    print("\nFirst SHA-256 Hash Output:", hash1.hex())

    hash2 = hashlib.sha256(hash1).digest()
    print("Final SHA-256d Hash Output:", hash2[::-1].hex())

    return hash2[::-1].hex()  # Convert to hex and reverse byte order for final output

def bits_to_target(bits):
    exponent = (bits >> 24) & 0xff
    mantissa = bits & 0xffffff
    target = mantissa * (1 << (8 * (exponent - 3)))
    return target

def validate_nonce_range(start_nonce, end_nonce):
    if not (0 <= start_nonce <= 0xFFFFFFFF):
        raise ValueError("Start nonce must be between 0 and 4,294,967,295")
    if not (0 < end_nonce <= 0xFFFFFFFF):
        raise ValueError("End nonce must be between 0 and 4,294,967,295")
    if start_nonce >= end_nonce:
        raise ValueError("Start nonce must be less than end nonce")

def validate_timestamp_range(start_timestamp, end_timestamp, latest_timestamp):
    current_time = int(time.time())
    max_future_time = current_time + 2 * 60 * 60  # 2 hours into the future

    if not (latest_timestamp <= start_timestamp <= max_future_time):
        raise ValueError("Start timestamp must be within 2 hours from the current time.")
    if not (start_timestamp < end_timestamp <= max_future_time):
        raise ValueError("End timestamp must be greater than start timestamp and within 2 hours from the current time.")

def get_nonce_range():
    start_nonce_input = input("Enter the starting nonce (0 to 4294967295, default 0, 'r' for random): ").strip()
    if start_nonce_input.lower() == 'r':
        start_nonce = random.randint(0, 0xFFFFFFFF)
    elif start_nonce_input == '':
        start_nonce = 0
    else:
        start_nonce = int(start_nonce_input)

    end_nonce_input = input("Enter the ending nonce (greater than starting nonce, default max, 'r' for random): ").strip()
    if end_nonce_input.lower() == 'r':
        end_nonce = random.randint(start_nonce + 1, 0xFFFFFFFF)
    elif end_nonce_input == '':
        end_nonce = 0xFFFFFFFF
    else:
        end_nonce = int(end_nonce_input)

    validate_nonce_range(start_nonce, end_nonce)
    return start_nonce, end_nonce

def get_timestamp_range(latest_timestamp):
    current_time = int(time.time())
    max_future_time = current_time + 2 * 60 * 60  # 2 hours into the future

    print(f"\nEnter a timestamp range.")
    print(f"Timestamp must be between {latest_timestamp} (latest block) and {max_future_time} (2 hours from now).")

    start_timestamp_input = input(f"Enter the starting timestamp (default: {latest_timestamp}): ").strip()
    if start_timestamp_input == '':
        start_timestamp = latest_timestamp
    else:
        start_timestamp = int(start_timestamp_input)

    end_timestamp_input = input(f"Enter the ending timestamp (must be greater than starting timestamp): ").strip()
    if end_timestamp_input == '':
        end_timestamp = max_future_time
    else:
        end_timestamp = int(end_timestamp_input)

    validate_timestamp_range(start_timestamp, end_timestamp, latest_timestamp)
    return start_timestamp, end_timestamp

def mine_block(block_info, nonce_range, timestamp_range, step_by_step=False):
    start_nonce, end_nonce = nonce_range
    start_timestamp, end_timestamp = timestamp_range

    target = bits_to_target(block_info['difficulty_target'])
    leading_zeros = calculate_leading_zeros(target)
    print(f"\nTarget (Difficulty): {target:064x}")
    print(f"Leading Zeros Required: {leading_zeros}")

    nonce = start_nonce
    timestamp = start_timestamp

    while timestamp <= end_timestamp:
        while nonce <= end_nonce:
            block_header = create_block_header(
                block_info['block_version'],
                block_info['prev_block_hash'],
                block_info['merkle_root'],
                timestamp,
                block_info['difficulty_target'],
                nonce
            )

            first_hash = hashlib.sha256(block_header).digest()
            final_hash = hashlib.sha256(first_hash).digest()

            print("------------------------------------------------------")
            print("Mining Iteration:")
            print("------------------------------------------------------")
            print(f"First SHA-256 Hash:    {first_hash.hex()}")
            print(f"Final SHA-256d Hash:   {final_hash[::-1].hex()}")
            print(f"Timestamp:            {timestamp}")
            print(f"Nonce:                {nonce}")
            print("------------------------------------------------------")
            print(f"{RED}Code by @BTC_Cracker for SoloSatoshi - Give me a follow or Comment on X{RESET}")

            if int.from_bytes(final_hash, 'little') < target:
                print(f"Success! Found valid block with nonce {nonce} and timestamp {timestamp}.")
                return nonce, timestamp, final_hash[::-1].hex()

            if step_by_step:
                while True:
                    choice = input("Options: [Enter] Next nonce, [c] Change nonce, [e] Exit: ").lower()
                    if choice == '':
                        nonce += 1
                        break
                    elif choice == 'c':
                        try:
                            new_nonce = int(input("Enter new nonce value: "))
                            if start_nonce <= new_nonce <= end_nonce:
                                nonce = new_nonce
                                break
                            else:
                                print(f"Nonce must be between {start_nonce} and {end_nonce}")
                        except ValueError:
                            print("Invalid input. Please enter a number.")
                    elif choice == 'e':
                        print("Exiting mining process.")
                        return None, None, None
                    else:
                        print("Invalid option. Please try again.")
            else:
                nonce += 1

        # If we've exhausted all nonces for this timestamp, move to the next timestamp
        timestamp += 1
        nonce = start_nonce

    print("No valid block found within the given nonce and timestamp range.")
    return None, None, None

def get_starting_nonce():
    while True:
        user_input = input("Enter starting nonce (press Enter for 0, 'r' for random, or a specific number): ").strip().lower()
        if user_input == '':
            return 0
        elif user_input == 'r':
            return random.randint(0, 0xFFFFFFFF)
        else:
            try:
                nonce = int(user_input)
                if 0 <= nonce <= 0xFFFFFFFF:
                    return nonce
                else:
                    print("Nonce must be between 0 and 4294967295. Please try again.")
            except ValueError:
                print("Invalid input. Please enter a valid number, 'r' for random, or press Enter for 0.")

def get_user_timestamp_range(last_block_timestamp):
    while True:
        user_input = input("Enter timestamp range in minutes (e.g., '4-12' for 4 to 12 minutes after the last block, or press Enter for default): ").strip()
        if user_input == "":
            return last_block_timestamp + 240, last_block_timestamp + 720  # Default: 4-12 minutes
        try:
            start, end = map(int, user_input.split('-'))
            if 0 <= start < end <= 30:
                return last_block_timestamp + start * 60, last_block_timestamp + end * 60
            else:
                print("Invalid range. Please enter two numbers between 0 and 30, with the first number smaller than the second.")
        except ValueError:
            print("Invalid input. Please enter two numbers separated by a hyphen, or press Enter for default.")


def auto_mine(block_info):
    target = bits_to_target(block_info['difficulty_target'])
    timestamp = int(time.time())
    best_hash = "f" * 64  # Start with worst possible hash
    best_nonce = 0
    best_zeros = 0

    print("Starting auto-mining process...")
    print(f"Target: {target:064x}")

    start_nonce = get_starting_nonce()
    total_iterations = 0xFFFFFFFF + 1  # Total number of possible nonces
    remaining_iterations = total_iterations - start_nonce

    for nonce in range(start_nonce, 0xFFFFFFFF + 1):
        block_header = create_block_header(
            block_info['block_version'],
            block_info['prev_block_hash'],
            block_info['merkle_root'],
            timestamp,
            block_info['difficulty_target'],
            nonce
        )

        first_hash = hashlib.sha256(block_header).digest()
        final_hash = hashlib.sha256(first_hash).digest()
        final_hash_hex = final_hash[::-1].hex()

        # Check if this hash meets the difficulty target
        if int.from_bytes(final_hash, 'little') < target:
            print("\nSuccess! Found a hash that meets the difficulty target.")
            print_block_data(block_info, nonce, timestamp, final_hash_hex)
            return

        # Update best hash if necessary
        zeros = count_leading_zeros(final_hash_hex)
        if zeros > best_zeros:
            best_zeros = zeros
            best_hash = final_hash_hex
            best_nonce = nonce

        # Update progress
        progress = ((nonce - start_nonce + 1) / remaining_iterations) * 100
        print(f"\rProgress: {progress:.2f}% | Best hash: {best_hash[:16]}... (Nonce: {best_nonce}, Zeros: {best_zeros})", end="", flush=True)

    print("\n\nMining complete. No hash found that meets the difficulty target.")
    print(f"Best hash found: {best_hash}")
    print(f"Nonce: {best_nonce}")
    print(f"Leading zeros: {best_zeros}")

def auto_mine_time(block_info):
    last_block_timestamp = int(block_info['timestamp'])
    start_timestamp, end_timestamp = get_user_timestamp_range(last_block_timestamp)
    timestamp_increment = 1  # Increment by 1 second, adjust if needed

    target = bits_to_target(block_info['difficulty_target'])
    best_hash = "f" * 64  # Start with worst possible hash
    best_nonce = 0
    best_timestamp = start_timestamp
    best_zeros = 0

    print("Starting auto-mining process with timestamp iteration...")
    print(f"Target: {target:064x}")
    print(f"Timestamp range: {format_timestamp(start_timestamp)} to {format_timestamp(end_timestamp)}")
    print(f"Unix timestamp range: {start_timestamp} to {end_timestamp}")

    start_nonce = get_starting_nonce()
    total_iterations = (0xFFFFFFFF + 1 - start_nonce) * ((end_timestamp - start_timestamp) // timestamp_increment + 1)
    current_iteration = 0

    for nonce in range(start_nonce, 0xFFFFFFFF + 1):
        for timestamp in range(start_timestamp, end_timestamp + 1, timestamp_increment):
            current_iteration += 1
            block_header = create_block_header(
                block_info['block_version'],
                block_info['prev_block_hash'],
                block_info['merkle_root'],
                timestamp,
                block_info['difficulty_target'],
                nonce
            )

            first_hash = hashlib.sha256(block_header).digest()
            final_hash = hashlib.sha256(first_hash).digest()
            final_hash_hex = final_hash[::-1].hex()

            # Check if this hash meets the difficulty target
            if int.from_bytes(final_hash, 'little') < target:
                print("\nSuccess! Found a hash that meets the difficulty target.")
                print_block_data(block_info, nonce, timestamp, final_hash_hex)
                return

            # Update best hash if necessary
            zeros = count_leading_zeros(final_hash_hex)
            if zeros > best_zeros:
                best_zeros = zeros
                best_hash = final_hash_hex
                best_nonce = nonce
                best_timestamp = timestamp

            # Update progress
            progress = (current_iteration / total_iterations) * 100
            print(f"\rProgress: {progress:.2f}% | Best: {best_hash[:16]}... (Nonce: {best_nonce}, Time: {best_timestamp}, Zeros: {best_zeros})", end="", flush=True)

    print("\n\nMining complete. No hash found that meets the difficulty target.")
    print(f"Best hash found: {best_hash}")
    print(f"Nonce: {best_nonce}")
    print(f"Timestamp: {best_timestamp}")
    print(f"Leading zeros: {best_zeros}")
    print(f"{RED}Code by @BTC_Cracker for SoloSatoshi - Give me a follow or Comment on X{RESET}")

def count_leading_zeros(hash_hex):
    return len(hash_hex) - len(hash_hex.lstrip('0'))

def print_block_data(block_info, nonce, timestamp, hash_hex):
    print(f"Block Height: {block_info['block_height']}")
    print(f"Previous Block Hash: {block_info['prev_block_hash']}")
    print(f"Merkle Root: {block_info['merkle_root']}")
    print(f"Timestamp: {timestamp}")
    print(f"Difficulty Target (Bits): {block_info['difficulty_target']}")
    print(f"Nonce: {nonce}")
    print(f"Block Hash: {hash_hex}")
    print(f"{RED}Code by @BTC_Cracker for SoloSatoshi - Give me a follow or Comment on X{RESET}")

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="BTC Blocker: A tool to simulate and verify Bitcoin block mining processes."
    )

    parser.add_argument(
        "-m", "--mode",
        choices=["mine", "verify", "auto", "autotime"],
        default="mine",
        help="Choose the mode: 'mine' for mining mode, 'verify' for verifier mode, 'auto' for automatic mining, or 'autotime' for automatic mining with timestamp iteration."
    )

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_arguments()

    if args.mode in ["mine", "auto", "autotime"]:
        latest_block_hash = get_latest_block_hash()

        if latest_block_hash:
            block_info = get_block_info(latest_block_hash)
            if args.mode == "mine":
                start_nonce, end_nonce = get_nonce_range()
                start_timestamp, end_timestamp = get_timestamp_range(block_info['timestamp'])
                mine_block(block_info, (start_nonce, end_nonce), (start_timestamp, end_timestamp), step_by_step=True)
            elif args.mode == "auto":
                auto_mine(block_info)
            else:  # autotime mode
                auto_mine_time(block_info)

    elif args.mode == "verify":
        verifier_mode()
