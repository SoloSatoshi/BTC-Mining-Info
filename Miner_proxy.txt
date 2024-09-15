#This code was written by @BTC_Cracker for the SoloSatoshi Blog. It is intended to be a proxy between the public pool
#and your miners.  It shows you what is going on with your miners as it is happening.
#It probably slows down mining.  It isn't intended for long-term use.  It's intended as a learning tool
#If you find a bug, you can message me, but I will prob tell you to fix it yourself.
#Do not abuse this code. This code is not free to use for commercial use.  Use it to LEARN!

import asyncio
import json
import hashlib
import argparse
from colorama import init, Fore, Style
from datetime import datetime

init(autoreset=True)

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

class MinerConnection:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.subscription_id = None
        self.authorized = False
        self.worker_name = None
        self.miner_name = None
        self.extranonce1 = None
        self.extranonce2_size = None

class PoolProxy:
    def __init__(self, pool_host, pool_port, local_port, start_nonce):
        self.pool_host = pool_host
        self.pool_port = pool_port
        self.local_port = local_port
        self.miners = {}
        self.start_nonce = start_nonce
        self.default_extranonce2_size = 4  # Default size, typically 4 bytes

    def parse_block_header(self, params):
        version = int(params[5], 16)
        prev_hash = params[1]
        merkle_root = params[2]
        timestamp = int(params[7], 16)
        bits = params[6]

        coinbase = bytes.fromhex(params[2] + params[3])
        height_hex = coinbase[42:46][::-1].hex()
        height = int(height_hex, 16)

        return {
            "height": height,
            "version": version,
            "prev_hash": prev_hash,
            "merkle_root": merkle_root,
            "timestamp": timestamp,
            "bits": bits,
        }

    def bits_to_difficulty(self, bits_hex):
        bits = int(bits_hex, 16)
        exponent = bits >> 24
        mantissa = bits & 0xFFFFFF
        target = mantissa * (2 ** (8 * (exponent - 3)))
        difficulty = (0xffff * 2**208) / target
        return int(difficulty)

    def print_readable_block_header(self, header, miner_id):
        miner = self.miners[miner_id]
        print(f"{Fore.RED}Code by @BTC_Cracker for SoloSatoshi - Give me a follow or Comment on X{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}New Job for miner {miner.miner_name} ({miner.ip}):{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Block Height: {Fore.WHITE}{header['height']}")
        print(f"{Fore.CYAN}Block Version: {Fore.WHITE}{header['version']}")
        print(f"{Fore.CYAN}Previous Block Hash: {Fore.WHITE}{header['prev_hash']}")
        print(f"{Fore.CYAN}Merkle Root: {Fore.WHITE}{header['merkle_root']}")
        print(f"{Fore.CYAN}Timestamp: {Fore.WHITE}{header['timestamp']} ({datetime.fromtimestamp(header['timestamp'])})")
        difficulty = self.bits_to_difficulty(header['bits'])
        print(f"{Fore.CYAN}Difficulty Target (Bits): {Fore.WHITE}{header['bits']} (Difficulty: {difficulty:,})")
        print(f"{Fore.CYAN}Starting Nonce: {Fore.WHITE}{self.start_nonce}")
        print()

    def modify_job(self, job_params, miner_id):
        miner = self.miners[miner_id]
        print(f"{Fore.RED}Code by @BTC_Cracker for SoloSatoshi - Give me a follow or Comment on X{Style.RESET_ALL}")
        print(f"Modifying job for miner {miner_id}")
        print(f"Extranonce1: {miner.extranonce1}, Extranonce2 size: {miner.extranonce2_size}")
        if miner.extranonce1 is None or miner.extranonce2_size is None:
            print(f"{Fore.RED}Error: Extranonce data not set for miner {miner_id}{Style.RESET_ALL}")
            return job_params  # Return unmodified job params

        extranonce2_size = miner.extranonce2_size or self.default_extranonce2_size
        extranonce2 = format(self.start_nonce, f'0{extranonce2_size*2}x').encode()

        coinbase1 = job_params[2]
        coinbase2 = job_params[3]

        # Construct the full coinbase transaction
        coinbase = bytes.fromhex(coinbase1) + bytes.fromhex(miner.extranonce1) + extranonce2 + bytes.fromhex(coinbase2)

        # Recalculate merkle root
        merkle_branches = job_params[4]
        merkle_root = double_sha256(coinbase)
        for branch in merkle_branches:
            merkle_root = double_sha256(merkle_root + bytes.fromhex(branch))

        # Update the job parameters
        job_params[2] = coinbase1 + miner.extranonce1
        job_params[3] = extranonce2.hex() + coinbase2

        print(f"Job modified. New extranonce2: {extranonce2.hex()}")

        # Increment the start_nonce for the next job
        self.start_nonce += 1

        return job_params

    async def handle_miner(self, reader, writer):
        miner_addr = writer.get_extra_info('peername')
        miner_ip = miner_addr[0]
        miner_port = miner_addr[1]
        miner_id = f"{miner_ip}:{miner_port}"
        self.miners[miner_id] = MinerConnection(miner_ip, miner_port)
        print(f"{Fore.GREEN}New miner connected from IP: {miner_ip}{Style.RESET_ALL}")

        pool_reader, pool_writer = await asyncio.open_connection(self.pool_host, self.pool_port)

        async def handle_pool_responses():
            buffer = ""
            while True:
                data = await pool_reader.read(4096)
                if not data:
                    break
                buffer += data.decode('utf-8', errors='ignore')
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    await self.process_pool_message(line, pool_writer, writer, miner_id)

        pool_task = asyncio.create_task(handle_pool_responses())

        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                decoded_data = data.decode('utf-8', errors='ignore')
                for line in decoded_data.splitlines():
                    await self.process_miner_message(line, pool_writer, writer, miner_id)
        finally:
            pool_task.cancel()
            writer.close()
            await writer.wait_closed()
            pool_writer.close()
            await pool_writer.wait_closed()
            del self.miners[miner_id]
            print(f"{Fore.YELLOW}Miner disconnected: {self.miners[miner_id].miner_name} ({miner_ip}){Style.RESET_ALL}")

    async def process_pool_message(self, message, pool_writer, miner_writer, miner_id):
        try:
            data = json.loads(message)
            miner = self.miners[miner_id]
            if 'result' in data:
                if data['id'] == 1:  # Subscription response
                    result = data['result']
                    if isinstance(result, list) and len(result) >= 2:
                        miner.subscription_id = result[1]
                        if len(result) >= 3:
                            miner.extranonce1 = result[2]
                        if len(result) >= 4:
                            miner.extranonce2_size = result[3]
                        print(f"{Fore.GREEN}Miner {miner.miner_name} ({miner.ip}) subscribed:{Style.RESET_ALL}")
                        print(f"  Subscription ID: {miner.subscription_id}")
                        print(f"  Extranonce1: {miner.extranonce1}")
                        print(f"  Extranonce2 size: {miner.extranonce2_size}")
                    else:
                        print(f"{Fore.RED}Error: Invalid subscription response{Style.RESET_ALL}")
                elif data['id'] == 2:  # Authorization response
                    if data.get('result'):
                        miner.authorized = True
                        print(f"{Fore.GREEN}Authorization successful for {miner.worker_name} (Miner {miner.miner_name} - {miner.ip}){Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}Authorization failed for {miner.worker_name} (Miner {miner.miner_name} - {miner.ip}){Style.RESET_ALL}")
            elif data.get('method') == 'mining.notify':
                print(f"\n{Fore.YELLOW}Original mining.notify from pool:{Style.RESET_ALL}")
                print(json.dumps(data, indent=2))

                if miner.extranonce1 is None or miner.extranonce2_size is None:
                    print(f"{Fore.YELLOW}Warning: Extranonce data not set for miner {miner_id}, passing job unmodified{Style.RESET_ALL}")
                else:
                    original_params = data['params'].copy()
                    data['params'] = self.modify_job(data['params'], miner_id)
                    print(f"\n{Fore.YELLOW}Modified mining.notify for miner:{Style.RESET_ALL}")
                    print(json.dumps(data, indent=2))
                    print(f"\n{Fore.CYAN}Extranonce1: {miner.extranonce1}, Extranonce2 size: {miner.extranonce2_size}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Original Extranonce2: {original_params[3][:miner.extranonce2_size*2]}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Modified Extranonce2: {data['params'][3][:miner.extranonce2_size*2]}{Style.RESET_ALL}")

                header = self.parse_block_header(data['params'])
                self.print_readable_block_header(header, miner_id)
                print(f"{Fore.CYAN}Modified starting nonce for miner {miner.miner_name} ({miner.ip}) to: {self.start_nonce}")
            elif 'error' in data and data['error'] is not None:
                print(f"\n{Fore.RED}ERROR for miner {miner.miner_name} ({miner.ip}):{Style.RESET_ALL}")
                print(json.dumps(data['error'], indent=2))

            modified_message = json.dumps(data) + '\n'
            miner_writer.write(modified_message.encode())
            await miner_writer.drain()

        except json.JSONDecodeError:
            print(f"Invalid JSON from pool for miner {miner_id}: {message}")
        except Exception as e:
            print(f"Error processing pool message for miner {miner_id}: {str(e)}")
            print(f"Message causing error: {message}")

    async def process_miner_message(self, message, pool_writer, miner_writer, miner_id):
        try:
            data = json.loads(message)
            miner = self.miners[miner_id]
            if data.get('method') == 'mining.subscribe':
                print(f"{Fore.YELLOW}Miner {miner.ip} subscribing{Style.RESET_ALL}")
            elif data.get('method') == 'mining.authorize':
                miner.worker_name = data['params'][0]
                miner.miner_name = miner.worker_name.split('.')[-1]  # Extract miner name
                print(f"{Fore.YELLOW}Miner {miner.miner_name} ({miner.ip}) authorizing as {miner.worker_name}{Style.RESET_ALL}")
            elif data.get('method') == 'mining.submit':
                if not miner.authorized:
                    print(f"{Fore.RED}Unauthorized share submission from {miner.miner_name} ({miner.ip}){Style.RESET_ALL}")
                    return
                print(f"\n{Fore.BLUE}Share Submitted by miner {miner.miner_name} ({miner.ip}):{Style.RESET_ALL}")
                print(f"Worker: {Fore.WHITE}{miner.worker_name}")
                print(f"Job ID: {Fore.WHITE}{data['params'][1]}")
                nonce_hex = data['params'][4]
                nonce_dec = int(nonce_hex, 16)
                print(f"Nonce: {Fore.WHITE}{nonce_hex} (Decimal: {nonce_dec})")

            await self.send_to_pool(pool_writer, data)
        except json.JSONDecodeError:
            print(f"Invalid JSON from miner {miner_id}: {message}")
        except Exception as e:
            print(f"Error processing miner message from {miner_id}: {e}")

    async def send_to_pool(self, writer, data):
        message = json.dumps(data) + '\n'
        writer.write(message.encode())
        await writer.drain()

    async def start_server(self):
        server = await asyncio.start_server(self.handle_miner, '0.0.0.0', self.local_port)
        addr = server.sockets[0].getsockname()
        print(f"{Fore.RED}Code by @BTC_Cracker for SoloSatoshi - Give me a follow or Comment on X{Style.RESET_ALL}")
        print(f'Serving on {addr}')
        async with server:
            await server.serve_forever()

async def main():
    parser = argparse.ArgumentParser(description="Bitcoin Mining Proxy with custom starting nonce by @BTC_Cracker")
    parser.add_argument('-nonce', type=int, default=0, help='Starting nonce value')
    args = parser.parse_args()

    proxy = PoolProxy('public-pool.io', 21496, 8888, args.nonce)
    await proxy.start_server()

if __name__ == "__main__":
    asyncio.run(main())
