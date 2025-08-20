from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import os
from datetime import datetime
import time
import threading
from collections import defaultdict
import logging

# --- Application Setup ---
app = Flask(__name__)
# Suppress insecure request warnings for verify=False
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# --- Logging Configuration ---
def log_info(message):
    app.logger.info(message)

def log_error(message):
    app.logger.error(message)

def log_debug(message):
    app.logger.debug(message)

def log_warning(message):
    app.logger.warning(message)


# --- Credential and Token Management ---

class CredentialManager:
    """Manages loading, caching, and rotation of credentials for sending likes."""
    def __init__(self, likes_per_batch=110):
        self.credentials_cache = {}
        self.server_indices = defaultdict(int)
        self.lock = threading.Lock()
        self.LIKES_PER_BATCH = likes_per_batch

    def load_credentials(self, server_name):
        """Loads credentials for a server from JSON files if not already in cache."""
        if server_name in self.credentials_cache:
            return self.credentials_cache[server_name]

        try:
            if server_name == "IND":
                filename = "ind.json"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                filename = "br.json"
            else:
                filename = "bd.json"
            
            with open(filename, "r") as f:
                credentials = json.load(f)
                self.credentials_cache[server_name] = credentials
                log_info(f"Loaded {len(credentials)} credentials for server {server_name}.")
                return credentials
        except FileNotFoundError:
            log_error(f"Credential file for server {server_name} not found.")
            return None
        except Exception as e:
            log_error(f"Error loading credentials for server {server_name}: {e}")
            return None

    def get_next_batch(self, server_name):
        """
        Gets the next batch of credentials for sending likes, implementing rotation logic.
        """
        with self.lock:
            credentials = self.load_credentials(server_name)
            if not credentials or len(credentials) < self.LIKES_PER_BATCH:
                log_warning(f"Not enough credentials for server {server_name} to form a full batch of {self.LIKES_PER_BATCH}.")
                return []

            start_index = self.server_indices[server_name]
            
            # If a full batch isn't available from the current position, reset to the beginning.
            if start_index + self.LIKES_PER_BATCH > len(credentials):
                log_info(f"End of credential list reached for {server_name}. Resetting index to start.")
                start_index = 0
                self.server_indices[server_name] = 0

            end_index = start_index + self.LIKES_PER_BATCH
            batch = credentials[start_index:end_index]
            
            # Update the index for the next request.
            self.server_indices[server_name] = end_index
            
            return batch

# --- JWT Generation and Caching ---
import my_pb2
import output_pb2

SESSION = requests.Session()
# Note: Storing keys in code is not recommended for production environments.
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# Global state for caching and locking
TOKEN_CACHE = {}
TOKEN_LOCKS = defaultdict(threading.Lock)
TOKEN_EXPIRATION_SECONDS = 7 * 3600  # 7 hours
STALE_TOKEN_GRACE_PERIOD_SECONDS = 300 # 5 minutes

credential_manager = CredentialManager(likes_per_batch=110)

def _generate_new_token(uid, password):
    """Helper function containing the logic to generate a new JWT token."""
    log_info(f"Attempting to generate new JWT token for UID: {uid}")
    token_data = getGuestAccessToken(uid, password)
    if not token_data or "access_token" not in token_data or not token_data["access_token"]:
        log_error(f"Failed to get Garena access token for UID: {uid}")
        return None

    access_token = token_data["access_token"]
    open_id = token_data["open_id"]

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    game_data = my_pb2.GameData()
    game_data.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    game_data.game_name = "Free Fire"
    game_data.game_version = 1
    game_data.version_code = "1.111.1"
    game_data.os_info = "iOS 18.4"
    game_data.device_type = "Handheld"
    game_data.user_id = str(uid)
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = 4
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    serialized_data = game_data.SerializeToString()
    padded_data = pad(serialized_data, AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(padded_data)
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive", "Accept-Encoding": "gzip", "Content-Type": "application/octet-stream",
        "Expect": "100-continue", "X-GA": "v1 1", "X-Unity-Version": "2018.4.11f1", "ReleaseVersion": "OB50",
    }

    try:
        response = SESSION.post(url, data=encrypted_data, headers=headers, timeout=30, verify=False)
        if response.status_code == 200:
            jwt_msg = output_pb2.Garena_420()
            jwt_msg.ParseFromString(response.content)
            if jwt_msg.token:
                log_info(f"Successfully generated new token for UID: {uid}")
                return jwt_msg.token
            else:
                log_error(f"Token generation succeeded but response contained no token for UID: {uid}")
                return None
        else:
            log_error(f"MajorLogin API returned status {response.status_code} for UID {uid}: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        log_error(f"Error during JWT request for UID {uid}: {e}")
        return None

def get_jwt_token(uid, password):
    """
    Gets a JWT token using a stale-while-revalidate cache strategy.
    This prevents service interruption during token updates under high load.
    """
    now = time.time()
    cached_token_info = TOKEN_CACHE.get(uid)

    # 1. If a fresh token exists, return it immediately.
    if cached_token_info and now < cached_token_info['expires_at']:
        return cached_token_info['token']

    # 2. Token is stale or absent. Try to acquire a lock without blocking.
    lock_acquired = TOKEN_LOCKS[uid].acquire(blocking=False)
    
    if lock_acquired:
        try:
            # 3. Lock acquired. We are responsible for the refresh.
            # Double-check if another thread refreshed it while we were acquiring the lock.
            cached_token_info = TOKEN_CACHE.get(uid)
            if cached_token_info and now < cached_token_info['expires_at']:
                return cached_token_info['token']

            new_token = _generate_new_token(uid, password)
            if new_token:
                TOKEN_CACHE[uid] = {'token': new_token, 'expires_at': now + TOKEN_EXPIRATION_SECONDS}
                return new_token
            else:
                # Generation failed. Allow old token to be used if within grace period.
                TOKEN_CACHE.pop(uid, None)
        finally:
            TOKEN_LOCKS[uid].release()
    
    # 4. Lock not acquired (another thread is refreshing) OR refresh failed.
    # Use the stale token if it's within the grace period.
    if cached_token_info and now < (cached_token_info['expires_at'] + STALE_TOKEN_GRACE_PERIOD_SECONDS):
        log_warning(f"Refresh in progress or failed for UID: {uid}. Returning stale token.")
        return cached_token_info['token']

    # 5. Stale token is too old. We must wait for the refresh to complete.
    log_warning(f"Token for {uid} is too stale. Waiting for active refresh to complete.")
    with TOKEN_LOCKS[uid]:
        refreshed_token = TOKEN_CACHE.get(uid)
        return refreshed_token['token'] if refreshed_token else None


def getGuestAccessToken(uid, password):
    headers = {
        "Host": "100067.connect.garena.com", "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "uid": str(uid), "password": str(password), "response_type": "token", "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    try:
        response = SESSION.post("https://100067.connect.garena.com/oauth/guest/token/grant",
                                headers=headers, data=data, verify=False, timeout=10)
        response.raise_for_status()
        data_response = response.json()
        if "error" in data_response:
             log_error(f"Auth error for UID {uid}: {data_response.get('error')}")
             return {"error": "auth_error"}
        return {"access_token": data_response.get("access_token"), "open_id": data_response.get("open_id")}
    except requests.exceptions.RequestException as e:
        log_error(f"Error getting guest access token for UID {uid}: {e}")
        return {"error": "request_failed"}

# --- Core Application Logic ---

def encrypt_message(plaintext):
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        log_error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        log_error(f"Error creating protobuf message: {e}")
        return None

async def send_request(session, encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)", 'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip", 'Authorization': f"Bearer {token}", 'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': "OB50"
        }
        async with session.post(url, data=edata, headers=headers) as response:
            if response.status != 200:
                log_error(f"Request failed with status code: {response.status}")
                return response.status
            return await response.text()
    except Exception as e:
        log_error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        protobuf_message = create_protobuf_message(uid, server_name)
        if not protobuf_message: return None
        encrypted_uid = encrypt_message(protobuf_message)
        if not encrypted_uid: return None

        credential_batch = credential_manager.get_next_batch(server_name)
        if not credential_batch:
            log_error(f"Could not get a batch of credentials for server {server_name}.")
            return None

        tasks = []
        async with aiohttp.ClientSession() as session:
            for cred in credential_batch:
                token = get_jwt_token(cred['uid'], cred['password'])
                if token:
                    tasks.append(send_request(session, encrypted_uid, token, url))
                else:
                    log_warning(f"Could not generate token for UID: {cred['uid']}. Skipping.")

            if not tasks:
                log_error("No valid JWT tokens could be generated for the batch.")
                return None
            
            log_info(f"Sending a batch of {len(tasks)} like requests for UID {uid}.")
            return await asyncio.gather(*tasks, return_exceptions=True)

    except Exception as e:
        log_error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.uid = int(uid)
        message.value = 1
        return message.SerializeToString()
    except Exception as e:
        log_error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    return encrypt_message(protobuf_data) if protobuf_data else None

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)", 'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip", 'Authorization': f"Bearer {token}", 'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': "OB50"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        binary_content = response.content
        return decode_protobuf(binary_content)
    except Exception as e:
        log_error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        log_error(f"Error decoding Protobuf data: {e}")
        return None

# --- API Endpoint ---

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        # Use one credential for initial check
        initial_credentials = credential_manager.load_credentials(server_name)
        if not initial_credentials:
            return jsonify({"error": f"Failed to load credentials for {server_name}."}), 500

        token = get_jwt_token(initial_credentials[0]['uid'], initial_credentials[0]['password'])
        if not token:
            return jsonify({"error": "Failed to generate initial JWT token."}), 500

        encrypted_uid = enc(uid)
        if not encrypted_uid:
            return jsonify({"error": "Encryption of UID failed."}), 500

        # Get player data before sending likes
        before_proto = make_request(encrypted_uid, server_name, token)
        if not before_proto:
            return jsonify({"error": "Failed to retrieve initial player info."}), 500
        
        data_before = json.loads(MessageToJson(before_proto))
        before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0))
        log_info(f"Likes before command for UID {uid}: {before_like}")

        # Determine correct URL based on server
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        # Send the batch of likes
        asyncio.run(send_multiple_requests(uid, server_name, url))

        # Get player data after sending likes
        after_proto = make_request(encrypted_uid, server_name, token)
        if not after_proto:
            return jsonify({"error": "Failed to retrieve player info after sending likes."}), 500
        
        data_after = json.loads(MessageToJson(after_proto))
        after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
        
        like_given = after_like - before_like
        result = {
            "LikesGivenByAPI": like_given,
            "LikesbeforeCommand": before_like,
            "LikesafterCommand": after_like,
            "PlayerNickname": data_after.get('AccountInfo', {}).get('PlayerNickname', ''),
            "PlayerRegion": data_after.get('AccountInfo', {}).get('region', ''),
            "PlayerLevel": data_after.get('AccountInfo', {}).get('level', ''),
            "UID": data_after.get('AccountInfo', {}).get('UID', 0),
            "status": 1 if like_given > 0 else 2
        }
        return jsonify(result)

    except Exception as e:
        log_error(f"Unhandled error in /like endpoint: {e}")
        return jsonify({"error": "An internal server error occurred.", "details": str(e)}), 500

if __name__ == '__main__':
    # For production, use a proper WSGI server like Gunicorn or uWSGI
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)