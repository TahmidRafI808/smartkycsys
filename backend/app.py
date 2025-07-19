import os
import boto3
import time
from datetime import datetime
from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import json
from botocore.exceptions import ClientError
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
import traceback
from datetime import datetime, timezone
import uuid
from eth_utils import to_checksum_address
# Load API credentials
load_dotenv()

# Filebase Configuration
FILEBASE_KEY = os.getenv("FILEBASE_KEY")
FILEBASE_SECRET = os.getenv("FILEBASE_SECRET")
FILEBASE_ENDPOINT = os.getenv("FILEBASE_ENDPOINT")
BUCKET_NAME = "kyc"
ADMIN_BUCKET = "kyc-admin"
BANK_BUCKET = "kyc-bank"
GATEWAY_URL = "https://ipfs.filebase.io/ipfs/"
BANK_PROFILE_TYPE = "bank"
# Blockchain Configuration
ZKSYNC_RPC_URL = os.getenv("ZKSYNC_RPC_URL")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
ADMIN_PRIVATE_KEY = os.getenv("ADMIN_PRIVATE_KEY")
ADMIN_WALLET = Account.from_key(ADMIN_PRIVATE_KEY).address

# Initialize Web3
w3 = Web3(Web3.HTTPProvider(ZKSYNC_RPC_URL))
if not w3.is_connected():
    raise Exception("Failed to connect to zkSync network")

# Load contract ABI
with open("KYCSystem.json") as f:
    contract_abi = json.load(f)["abi"]
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)

# Configure Filebase client
s3 = boto3.client(
    's3',
    endpoint_url=FILEBASE_ENDPOINT,
    aws_access_key_id=FILEBASE_KEY,
    aws_secret_access_key=FILEBASE_SECRET
)

# Flask app
app = Flask(__name__)
app.secret_key = "supersecret"

def approve_bank_on_chain(wallet):
    """Approve bank on blockchain"""
    try:
        checksum_wallet = Web3.to_checksum_address(wallet)
        
        # Verify contract admin matches our admin
        contract_admin = contract.functions.admin().call()
        if contract_admin.lower() != ADMIN_WALLET.lower():
            print(f"CRITICAL: Contract admin mismatch! "
                  f"Contract has {contract_admin}, we're using {ADMIN_WALLET}")
            return False

        # Build and send transaction
        tx = contract.functions.approveBank(checksum_wallet).build_transaction({
            'chainId': w3.eth.chain_id,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(ADMIN_WALLET),
            'from': ADMIN_WALLET  # Crucial for proper gas estimation
        })
        
        # Estimate gas properly
        tx['gas'] = contract.functions.approveBank(checksum_wallet).estimate_gas({
            'from': ADMIN_WALLET
        })

        signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)  # Use snake_case
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt.status != 1:
            print(f"Transaction reverted! TX hash: {tx_hash.hex()}")
            return False
            
        return True
    except Exception as e:
        print(f"Error approving bank: {str(e)}")
        traceback.print_exc()
        return False


def move_loan_request_to_active_loans(bank_wallet, user_wallet, request_key):
    """Move loan request to bank's active_loans folder"""
    try:
        # Generate unique filename with timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        new_key = f"active_loans/{bank_wallet}/{user_wallet}_{timestamp}_{uuid.uuid4().hex}.json"
        
        # Copy to new location
        s3.copy_object(
            Bucket=BANK_BUCKET,
            Key=new_key,
            CopySource={'Bucket': BUCKET_NAME, 'Key': request_key}
        )
        
        # Delete original
        s3.delete_object(Bucket=BUCKET_NAME, Key=request_key)
        return True
    except Exception as e:
        print(f"Error moving loan request: {e}")
        traceback.print_exc()
        return False
def get_user_ratings(wallet):
    """Get all ratings for a user from Filebase"""
    try:
        prefix = f"{wallet}/ratings/"
        objects = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=prefix).get('Contents', [])
        ratings = []
        
        for obj in objects:
            try:
                # Skip if it's a directory
                if obj['Key'].endswith('/'):
                    continue
                    
                response = s3.get_object(Bucket=BUCKET_NAME, Key=obj['Key'])
                rating_data = json.loads(response['Body'].read().decode('utf-8'))
                
                # Get bank profile for name display
                bank_wallet = rating_data.get('bank_wallet')
                if bank_wallet:
                    bank_profile = get_bank_profile(bank_wallet)
                    rating_data['bank_name'] = bank_profile['name'] if bank_profile else bank_wallet
                else:
                    rating_data['bank_name'] = "Unknown Bank"
                
                ratings.append(rating_data)
            except Exception as e:
                print(f"Error processing rating file {obj['Key']}: {e}")
                continue
        
        # Sort by timestamp (newest first)
        ratings.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
        return ratings
    except Exception as e:
        print(f"Error getting ratings: {e}")
        traceback.print_exc()
        return []

def format_timestamp(timestamp):
    """Convert Unix timestamp to readable format"""
    try:
        # Convert to datetime object and format
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "Invalid timestamp"

# Register the custom filter
app.jinja_env.filters['format_timestamp'] = format_timestamp

def get_all_users():
    """Get all user wallet addresses from blockchain by scanning events"""
    try:
        # Get latest block to determine scan range
        latest_block = w3.eth.block_number
        # Start scanning from 5000 blocks ago to cover all possible events
        from_block = max(0, latest_block - 5000)
        
        # Create event filter for UserProfileCreated
        event_signature = w3.keccak(text="UserProfileCreated(address)").hex()
        event_filter = {
            'fromBlock': from_block,
            'toBlock': latest_block,
            'topics': [event_signature],
            'address': CONTRACT_ADDRESS
        }
        
        # Get event logs
        logs = w3.eth.get_logs(event_filter)
        
        # Extract wallet addresses from event data
        user_wallets = set()
        for log in logs:
            # Extract wallet address from event data
            # Address is the second topic (index 1) in the log
            if len(log['topics']) > 1:
                # Convert from bytes32 to address (last 20 bytes)
                address_bytes = log['topics'][1][-20:]
                wallet = Web3.to_checksum_address(address_bytes.hex())
                user_wallets.add(wallet)
                
        return list(user_wallets)
    
    except Exception as e:
        print(f"Error getting all users: {e}")
        traceback.print_exc()
        return []

# Helper Functions
def get_profile_type(wallet_address):
    try:
        # Convert to checksum address
        checksum_address = Web3.to_checksum_address(wallet_address)
        profile_type = contract.functions.getProfileType(checksum_address).call()
        return {
            0: "none",
            1: "user",
            2: "bank",
            3: "admin"
        }.get(profile_type, "none")
    except Exception as e:
        print(f"Error getting profile type: {e}")
        return "none"
    

# Helper function to get pending loan requests for a bank
def get_pending_requests_for_bank(bank_wallet):
    bank_wallet = bank_wallet.strip().lower()
    try:
        # Get directed loan requests
        prefix = f"loan_requests/{bank_wallet}/"
        objects = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=prefix).get('Contents', [])
        requests = []
        
        for obj in objects:
            response = s3.get_object(Bucket=BUCKET_NAME, Key=obj['Key'])
            request_data = json.loads(response['Body'].read())
            
            # Get user profile for name
            user_profile = get_user_profile(request_data['user_wallet'])
            if user_profile:
                request_data['name'] = user_profile['full_name']
                request_data['key'] = obj['Key']  # Add the object key
                requests.append(request_data)
        
        return requests
    except Exception as e:
        print(f"Error getting pending requests: {e}")
        return []

def create_user_profile(wallet, data):
    """Create user profile on blockchain using user's wallet"""
    try:
        user_wallet = Web3.to_checksum_address(wallet)
        
        # Get pending nonce
        nonce = w3.eth.get_transaction_count(user_wallet, 'pending')
        
        # Build transaction without gas first
        tx = contract.functions.createUserProfile(
            data['full_name'],
            data['email'],
            data['phone'],
            data['current_address'],
            data['permanent_address'],
            data['current_job'],
            data['nid_number'],
            data['profile_pic_cid'],
            data['property_docs_cid']
        ).build_transaction({
            'chainId': w3.eth.chain_id,
            'gasPrice': w3.eth.gas_price,
            'nonce': nonce,
            'from': user_wallet
        })
        
        # Estimate gas
        try:
            tx['gas'] = contract.functions.createUserProfile(
                data['full_name'],
                data['email'],
                data['phone'],
                data['current_address'],
                data['permanent_address'],
                data['current_job'],
                data['nid_number'],
                data['profile_pic_cid'],
                data['property_docs_cid']
            ).estimate_gas({
                'from': user_wallet,
                'nonce': nonce
            })
        except Exception as e:
            print(f"Gas estimation failed: {e}")
            tx['gas'] = 3000000  # Fallback gas limit
        
        return {
            'to': CONTRACT_ADDRESS,
            'data': tx['data'],
            'value': 0,
            'gas': hex(tx['gas']),
            'gasPrice': hex(tx['gasPrice']),
            'nonce': hex(tx['nonce']),
            'chainId': hex(tx['chainId'])
        }
    except Exception as e:
        print(f"Error creating user profile on blockchain: {e}")
        traceback.print_exc()
        return None

def create_bank_profile(wallet, data):
    """Create bank profile on blockchain"""
    try:
        # Prepare transaction
        tx = contract.functions.createBankProfile(
            data['name'],
            data['email'],
            data['phone'],
            data['license_number'],
            data['logo_cid']
        ).build_transaction({
            'chainId': w3.eth.chain_id,
            'gas': 2000000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(ADMIN_WALLET),
        })
        
        # Sign and send
        signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return receipt.status == 1
    except Exception as e:
        print(f"Error creating bank profile on blockchain: {e}")
        return False

def request_verification(user_wallet, verifier_wallet):
    """Request verification on blockchain"""
    try:
        # Prepare transaction
        tx = contract.functions.requestVerification(verifier_wallet).build_transaction({
            'chainId': w3.eth.chain_id,
            'gas': 1000000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(ADMIN_WALLET),
        })
        
        # Sign and send
        signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return receipt.status == 1
    except Exception as e:
        print(f"Error requesting verification on blockchain: {e}")
        return False

def verify_user(user_wallet):
    """Verify user on blockchain"""
    try:
        # Prepare transaction
        tx = contract.functions.verifyUser(user_wallet).build_transaction({
            'chainId': w3.eth.chain_id,
            'gas': 1000000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(ADMIN_WALLET),
        })
        
        # Sign and send
        signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return receipt.status == 1
    except Exception as e:
        print(f"Error verifying user on blockchain: {e}")
        return False

def get_user_profile(wallet):
    try:
        checksum_wallet = Web3.to_checksum_address(wallet)
        profile = contract.functions.getUserProfile(checksum_wallet).call()
        
        # Check if profile exists
        if not profile or not profile[0]:  # fullName is empty
            return None
        return {
            'full_name': profile[0],
            'email': profile[1],
            'phone': profile[2],
            'current_address': profile[3],
            'permanent_address': profile[4],
            'current_job': profile[5],
            'nid_number': profile[6],
            'profile_pic_cid': profile[7],
            'property_docs_cid': profile[8],
            'verification_status': profile[9],
            'verified_by': profile[10]
        }
    except Exception as e:
        if "User profile does not exist" in str(e):
            return None
        print(f"Error getting user profile: {e}")
        return None

def get_bank_profile(wallet):
    try:
        # Convert to checksum address
        checksum_wallet = Web3.to_checksum_address(wallet)
        profile = contract.functions.getBankProfile(checksum_wallet).call()
        return {
            'name': profile[0],
            'email': profile[1],
            'phone': profile[2],
            'license_number': profile[3],
            'logo_cid': profile[4],
            'approved': profile[5]
        }
    except Exception as e:
        print(f"Error getting bank profile: {e}")
        return None
def get_total_users():
    """Get total number of user profiles from blockchain by scanning events"""
    try:
        # Get contract address
        contract_address = Web3.to_checksum_address(CONTRACT_ADDRESS)
        
        # Get event signature
        event_signature = w3.keccak(text="UserProfileCreated(address)").hex()
        
        # Create filter parameters
        event_filter = {
            'fromBlock': 0,  # Start from genesis block
            'toBlock': 'latest',
            'topics': [event_signature],
            'address': contract_address
        }
        
        # Get logs with error handling
        try:
            logs = w3.eth.get_logs(event_filter)
        except Exception as e:
            print(f"Error getting logs: {e}")
            # Fallback to latest 5000 blocks if full scan fails
            latest_block = w3.eth.block_number
            event_filter['fromBlock'] = max(0, latest_block - 5000)
            logs = w3.eth.get_logs(event_filter)
        
        # Use set to avoid duplicate wallet entries
        user_wallets = set()
        
        for log in logs:
            try:
                # Extract wallet address from event data
                if len(log['topics']) > 1:
                    # Address is the second topic (index 1)
                    address_bytes = log['topics'][1][-20:]
                    wallet = Web3.to_checksum_address(address_bytes.hex())
                    user_wallets.add(wallet)
            except Exception as e:
                print(f"Error processing log: {e}")
                continue
                
        return len(user_wallets)
    
    except Exception as e:
        print(f"Critical error in get_total_users: {e}")
        traceback.print_exc()
        
        # Fallback to contract state if available
        try:
            # This might not work for all contracts, but worth trying
            return contract.functions.userCount().call()
        except:
            return 0   

# Add this helper function
def get_active_deals(wallet):
    try:
        # 1. Get active deals from blockchain
        deal_counter = contract.functions.dealCounter().call()
        active_deals = []
        
        for deal_id in range(1, deal_counter + 1):
            try:
                deal = contract.functions.loanDeals(deal_id).call()
                user = deal[0]
                bank = deal[1]
                
                if (user.lower() == wallet.lower() or 
                    bank.lower() == wallet.lower()):
                    
                    status = "pending"
                    if deal[7]:  # completed
                        status = "completed"
                    elif deal[6]:  # accepted
                        status = "active"
                    
                    monthly_payment = deal[5]  # This is a boolean
                    
                    active_deals.append({
                        'deal_id': deal_id,
                        'user': user,
                        'bank': bank,
                        'amount': deal[2],
                        'start_date': deal[3],  # Unix timestamp
                        'deadline': deal[4],    # Unix timestamp
                        'monthly_payment': monthly_payment,
                        'status': status,
                        'source': 'blockchain'
                    })
            except Exception as e:
                print(f"Error processing deal {deal_id}: {e}")
                continue
        
        # 2. Get active loans from Filebase bucket
        try:
            # For banks: active_loans/{bank_wallet}/
            # For users: active_loans/*/{user_wallet}_*
            prefix_bank = f"active_loans/{wallet}/"
            prefix_user = f"active_loans/"
            
            # Get all objects in active_loans folder
            objects = s3.list_objects_v2(Bucket=BANK_BUCKET, Prefix=prefix_user).get('Contents', [])
            
            for obj in objects:
                key = obj['Key']
                
                # Check if this loan belongs to the current wallet
                is_bank_loan = key.startswith(prefix_bank)
                is_user_loan = wallet.lower() in key.lower() and "/" in key.replace(prefix_user, "", 1)
                
                if is_bank_loan or is_user_loan:
                    try:
                        response = s3.get_object(Bucket=BANK_BUCKET, Key=key)
                        loan_data = json.loads(response['Body'].read())
                        
                        # Add to active deals with Filebase source marker
                        active_deals.append({
                            'source': 'filebase',
                            'user': loan_data['user_wallet'],
                            'bank': loan_data['bank_wallet'],
                            'amount': loan_data['amount'],
                            'duration': loan_data['duration'],
                            'monthly_payment': loan_data['payment_type'] == 'monthly',
                            'status': 'active',
                            'start_date': loan_data['timestamp'],
                            'file_key': key  # For reference
                        })
                    except Exception as e:
                        print(f"Error processing active loan {key}: {e}")
        except Exception as e:
            print(f"Error retrieving active loans from Filebase: {e}")
                
        return active_deals
    except Exception as e:
        print(f"Error getting active deals: {e}")
        return []
    
# Routes
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/test-tx')
def test_tx():
    """Test endpoint for blockchain connection"""
    try:
        test_account = w3.eth.account.create()
        tx = {
            'to': test_account.address,
            'value': 0,
            'gas': 21000,
            'gasPrice': w3.eth.gas_price,
            'nonce': 0,
            'chainId': w3.eth.chain_id
        }
        return jsonify({
            'success': True,
            'network': f"zkSync Sepolia (Chain ID: {w3.eth.chain_id})",
            'gas_price': w3.eth.gas_price,
            'latest_block': w3.eth.block_number,
            'test_tx': tx
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.route('/create-profile')
def create_profile():
    wallet = request.args.get("wallet", "").strip().lower()
    if not wallet:
        flash("Wallet address is required.", "danger")
        return redirect("/")
    
    # Check profile type on blockchain
    profile_type = get_profile_type(wallet)
    if profile_type != "none":
        flash("This wallet already has a profile.", "warning")
        return redirect("/")
    
    return render_template("profile.html", user_data={}, wallet=wallet, profile_url=None, ipfs_urls={})

@app.route('/verify-profile-creation', methods=['POST'])
def verify_profile_creation():
    data = request.json
    tx_hash = data.get('txHash')
    wallet = Web3.to_checksum_address(data.get('wallet'))
    
    try:
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        if receipt.status == 1:
            # Confirm profile exists
            profile_type = get_profile_type(wallet)
            if profile_type != "none":
                return jsonify(success=True)
    except Exception as e:
        print(f"Verification failed: {e}")
    
    return jsonify(success=False, error="Profile creation failed"), 400

@app.route('/login', methods=['GET'])
def login():
    # Validate and normalize wallet address
    try:
        wallet = Web3.to_checksum_address(request.args.get("wallet", "").strip())
    except:
        flash("Invalid wallet address", "danger")
        return redirect("/")
    
    # Get profile type from blockchain with error handling
    try:
        profile_type = get_profile_type(wallet)
    except Exception as e:
        print(f"Error getting profile type: {e}")
        flash("Error connecting to blockchain", "danger")
        return redirect("/")
    
    # Handle profile types
    if profile_type == "none":
        flash("No profile found. Please create one", "danger")
        return redirect(url_for('create_profile', wallet=wallet))
        
    elif profile_type == "user":
        session['user_logged_in'] = True
        session['user_wallet'] = wallet
        flash("User login successful!", "success")
        return redirect(url_for('view_profile', wallet=wallet))
        
    elif profile_type == "bank":
        bank_profile = get_bank_profile(wallet)
        if bank_profile and bank_profile['approved']:
            session['bank_logged_in'] = True
            session['bank_wallet'] = wallet
            flash("Bank authority login successful!", "success")
            # FIX: Changed 'bank-profile' to 'view_profile'
            return redirect(url_for('view_profile', wallet=wallet))
        else:
            flash("Bank profile not yet approved by admin", "warning")
            return redirect("/")
            
    elif profile_type == "admin":
    # Verify it's the actual admin wallet
     if wallet.lower() == ADMIN_WALLET.lower():
        session['admin_logged_in'] = True
        session['admin_wallet'] = wallet
        flash("Admin login successful!", "success")
        return redirect(url_for('admin_dashboard'))
     else:
        flash("Unauthorized admin access", "danger")
        return redirect("/")
        
    else:
        # Fallback for unexpected profile types
        flash("Unsupported profile type", "danger")
        return redirect("/")

@app.route('/submit-profile', methods=['POST'])
def submit_profile():
    # Get form data
    wallet = request.form.get('wallet_address', '').strip().lower()
    if not wallet:
        return jsonify({'success': False, 'message': 'Wallet address is missing'}), 400

    # Validate wallet address
    if not Web3.is_address(wallet):
        return jsonify({'success': False, 'message': 'Invalid wallet address'}), 400

    # Get all form fields
    user_data = {
        'full_name': request.form.get('full_name', ''),
        'email': request.form.get('email', ''),
        'phone': request.form.get('phone', ''),
        'current_address': request.form.get('current_address', ''),
        'permanent_address': request.form.get('permanent_address', ''),
        'current_job': request.form.get('current_job', ''),
        'nid_number': request.form.get('nid_number', '')
    }

    # Validate required fields
    required_fields = ['full_name', 'email', 'phone', 'current_address', 
                       'permanent_address', 'current_job', 'nid_number']
    for field in required_fields:
        if not user_data[field]:
            return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400

    # Handle file uploads
    profile_pic = request.files.get('profile_picture')
    property_docs = request.files.getlist('property_doc[]')

    # Process profile picture
    profile_pic_cid = ""
    if profile_pic and profile_pic.filename != '':
        try:
            profile_key = f"{wallet}/profile_picture.jpg"
            s3.upload_fileobj(profile_pic, BUCKET_NAME, profile_key, ExtraArgs={'Metadata': {'cid': 'true'}})
            profile_resp = s3.head_object(Bucket=BUCKET_NAME, Key=profile_key)
            profile_pic_cid = profile_resp['Metadata'].get('cid', '')
        except ClientError as e:
            print(f"Error uploading profile picture: {e}")
            return jsonify({'success': False, 'message': 'Failed to upload profile picture'}), 500

    # Process property documents
    property_docs_cid = ""
    if property_docs:
        try:
            for i, doc in enumerate(property_docs):
                if doc.filename == '':
                    continue
                ext = os.path.splitext(doc.filename)[1] or '.bin'
                doc_key = f"{wallet}/docs/{i}{ext}"
                s3.upload_fileobj(doc, BUCKET_NAME, doc_key, ExtraArgs={'Metadata': {'cid': 'true'}})
                doc_resp = s3.head_object(Bucket=BUCKET_NAME, Key=doc_key)
                
                # Store first CID for simplicity (in real app, might store all)
                if not property_docs_cid:
                    property_docs_cid = doc_resp['Metadata'].get('cid', '')
        except ClientError as e:
            print(f"Error uploading property documents: {e}")
            return jsonify({'success': False, 'message': 'Failed to upload property documents'}), 500

    user_data['profile_pic_cid'] = profile_pic_cid
    user_data['property_docs_cid'] = property_docs_cid

    # Prepare blockchain transaction
    try:
        user_wallet = Web3.to_checksum_address(wallet)
        nonce = w3.eth.get_transaction_count(user_wallet, 'pending')  # Pending nonce
        
        # Build transaction without gas first
        tx = contract.functions.createUserProfile(
            user_data['full_name'],
            user_data['email'],
            user_data['phone'],
            user_data['current_address'],
            user_data['permanent_address'],
            user_data['current_job'],
            user_data['nid_number'],
            user_data['profile_pic_cid'],
            user_data['property_docs_cid']
        ).build_transaction({
            'chainId': w3.eth.chain_id,
            'gasPrice': w3.eth.gas_price,
            'nonce': nonce,
            'from': user_wallet
        })
        
        # Estimate gas
        try:
            tx['gas'] = contract.functions.createUserProfile(
                user_data['full_name'],
                user_data['email'],
                user_data['phone'],
                user_data['current_address'],
                user_data['permanent_address'],
                user_data['current_job'],
                user_data['nid_number'],
                user_data['profile_pic_cid'],
                user_data['property_docs_cid']
            ).estimate_gas({
                'from': user_wallet,
                'nonce': nonce
            })
        except Exception as e:
            print(f"Gas estimation failed: {e}")
            tx['gas'] = 3000000  # Fallback gas limit
        
        # Prepare response
        tx_data = {
            'from': user_wallet,
            'to': CONTRACT_ADDRESS,
            'data': tx['data'],
            'value': hex(tx.get('value', 0)),
            'gas': hex(tx['gas']),
            'gasPrice': hex(tx['gasPrice']),
            'nonce': hex(tx['nonce']),
            'chainId': hex(tx['chainId'])
        }
        
        return jsonify({
            'success': True,
            'message': 'Please sign the transaction in your wallet',
            'txData': tx_data,
            'wallet': wallet
        })
        
    except Exception as e:
        print(f"Error creating user profile transaction: {e}")
        traceback.print_exc()
        return jsonify({
            'success': False, 
            'message': f'Failed to prepare blockchain transaction: {str(e)}',
            'traceback': traceback.format_exc()
        }), 500
    
@app.route('/view-profile/<wallet>')
def view_profile(wallet):
    # Normalize wallet address
    wallet = wallet.strip().lower()
    
    # Get profile type
    profile_type = get_profile_type(wallet)
    
    if profile_type == "user":
        # Get user profile from blockchain
        profile = get_user_profile(wallet)
        if not profile:
            flash("User profile not found", "danger")
            return redirect("/")
            
        # Get profile picture URL
        profile_pic_url = f"{GATEWAY_URL}{profile['profile_pic_cid']}" if profile['profile_pic_cid'] else None
        
        # Get property documents
        property_docs = []
        if profile['property_docs_cid']:
            property_docs.append({
                'url': f"{GATEWAY_URL}{profile['property_docs_cid']}",
                'filename': "Property Documents"
            })
        
        # Get active deals for this user
        deals = get_active_deals(wallet)
        
        # Get user ratings
        ratings = get_user_ratings(wallet)
        
        return render_template("view_profile.html", 
                              data=profile,
                              profile_pic_url=profile_pic_url,
                              property_docs=property_docs,
                              wallet=wallet,
                              profile_type=profile_type,
                              deals=deals,
                              ratings=ratings,
                              gateway_url=GATEWAY_URL)
    
    elif profile_type == "bank":
        # Get bank profile from blockchain
        profile = get_bank_profile(wallet)
        if not profile:
            flash("Bank profile not found", "danger")
            return redirect("/")
            
        # Get logo URL
        profile_pic_url = f"{GATEWAY_URL}{profile['logo_cid']}" if profile['logo_cid'] else None
        
        # Get active deals for this bank
        deals = get_active_deals(wallet)
    
        # Get pending loan requests
        loan_requests = get_pending_requests_for_bank(wallet)
    
        if (session.get('bank_logged_in') and session['bank_wallet'].lower() == wallet) or \
           session.get('admin_logged_in'):

        
            return render_template("bank-profile.html", 
                              data=profile,
                              profile_pic_url=profile_pic_url,
                              wallet=wallet,
                              deals=deals,
                              loan_requests=loan_requests,
                              gateway_url=GATEWAY_URL)
    
    else:
        flash("Profile not found", "danger")
        return redirect("/")

def get_user_ratings(wallet):
    """Get all ratings for a user from Filebase"""
    try:
        prefix = f"{wallet}/ratings/"
        objects = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=prefix).get('Contents', [])
        ratings = []
        
        for obj in objects:
            try:
                response = s3.get_object(Bucket=BUCKET_NAME, Key=obj['Key'])
                rating_data = json.loads(response['Body'].read())
                
                # Get bank profile for name display
                bank_profile = get_bank_profile(rating_data['bank_wallet'])
                rating_data['bank_name'] = bank_profile['name'] if bank_profile else rating_data['bank_wallet']
                
                ratings.append(rating_data)
            except Exception as e:
                print(f"Error processing rating file {obj['Key']}: {e}")
                continue
        
        # Sort by timestamp (newest first)
        ratings.sort(key=lambda x: x['timestamp'], reverse=True)
        return ratings
    except Exception as e:
        print(f"Error getting ratings: {e}")
        return []

@app.route('/create-bank-profile')
def create_bank_profile():
    wallet = request.args.get("wallet", "").strip().lower()
    if not wallet:
        flash("Wallet address is required.", "danger")
        return redirect("/")
    
    # Check profile type on blockchain
    profile_type = get_profile_type(wallet)
    if profile_type != "none":
        flash("This wallet already has a profile.", "warning")
        return redirect("/")
    
    return render_template("bank_profile.html", wallet=wallet)

@app.route('/submit-bank-profile', methods=['POST'])
def submit_bank_profile():
    # Get form data
    wallet = request.form.get('wallet_address', '').strip().lower()
    if not wallet:
        return jsonify({'success': False, 'message': 'Wallet address is missing'}), 400

    # Validate wallet address
    if not Web3.is_address(wallet):
        return jsonify({'success': False, 'message': 'Invalid wallet address'}), 400

    # Get form fields
    name = request.form.get('bank_name', '')
    email = request.form.get('email', '')
    phone = request.form.get('phone', '')
    license_number = request.form.get('license_number', '')
    logo = request.files.get('bank_logo')

    # Validate required fields
    required_fields = ['bank_name', 'email', 'phone', 'license_number']
    for field in required_fields:
        if not request.form.get(field):
            return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400

    # Upload logo to IPFS (to bank bucket)
    logo_cid = ""
    if logo and logo.filename != '':
        try:
            logo_key = f"{wallet}/logo.jpg"
            s3.upload_fileobj(logo, BANK_BUCKET, logo_key, ExtraArgs={'Metadata': {'cid': 'true'}})
            logo_resp = s3.head_object(Bucket=BANK_BUCKET, Key=logo_key)
            logo_cid = logo_resp['Metadata'].get('cid', '')
        except ClientError as e:
            print(f"Error uploading bank logo: {e}")
            return jsonify({'success': False, 'message': 'Failed to upload bank logo'}), 500

    # Save profile metadata to ADMIN_BUCKET for approval
    try:
        profile_data = {
            'bank_name': name,
            'email': email,
            'phone': phone,
            'license_number': license_number,
            'logo_cid': logo_cid,
            'wallet': wallet,
            'timestamp': int(time.time()),
            'profile_type': 'bank'
        }
        
        metadata_key = f"{wallet}/metadata.json"
        s3.put_object(
            Bucket=ADMIN_BUCKET,
            Key=metadata_key,
            Body=json.dumps(profile_data),
            ContentType='application/json'
        )
        
        # Debug log to verify metadata creation
        print(f"Bank profile metadata saved to admin bucket: {metadata_key}")
    except Exception as e:
        print(f"Error saving bank profile metadata: {e}")
        traceback.print_exc()
        return jsonify({
            'success': False, 
            'message': 'Failed to save bank profile for approval',
            'error': str(e)
        }), 500

    # Prepare blockchain transaction
    try:
        bank_wallet = Web3.to_checksum_address(wallet)
        nonce = w3.eth.get_transaction_count(bank_wallet, 'pending')
        
        # Build transaction
        tx = contract.functions.createBankProfile(
            name,
            email,
            phone,
            license_number,
            logo_cid
        ).build_transaction({
            'chainId': w3.eth.chain_id,
            'gasPrice': w3.eth.gas_price,
            'nonce': nonce,
            'from': bank_wallet
        })
        
        # Estimate gas
        try:
            tx['gas'] = contract.functions.createBankProfile(
                name,
                email,
                phone,
                license_number,
                logo_cid
            ).estimate_gas({
                'from': bank_wallet,
                'nonce': nonce
            })
        except Exception as e:
            print(f"Gas estimation failed: {e}")
            tx['gas'] = 2000000  # Fallback gas limit
        
        # Prepare response
        tx_data = {
            'to': CONTRACT_ADDRESS,
            'data': tx['data'],
            'value': hex(0),
            'gas': hex(tx['gas']),
            'gasPrice': hex(tx['gasPrice']),
            'nonce': hex(tx['nonce']),
            'chainId': hex(tx['chainId'])
        }
        
        return jsonify({
            'success': True,
            'message': 'Please sign the transaction in your wallet',
            'txData': tx_data,
            'wallet': wallet
        })
        
    except Exception as e:
        print(f"Error creating bank profile transaction: {e}")
        traceback.print_exc()
        return jsonify({
            'success': False, 
            'message': f'Failed to prepare blockchain transaction: {str(e)}',
            'traceback': traceback.format_exc()
        }), 500

@app.route('/get-bank-deals')
def get_bank_deals():
    bank_wallet = request.args.get('bank', '').strip()
    if not bank_wallet:
        return jsonify([])
    
    try:
        deals = get_active_deals(bank_wallet)
        return jsonify(deals)
    except Exception as e:
        print(f"Error fetching bank deals: {e}")
        return jsonify([])

@app.route('/get-all-chat-partners/<bank_wallet>')
def get_all_chat_partners(bank_wallet):
    """Get all users who have ever chatted with the bank"""
    try:
        prefix = "chats/"
        partners = set()
        
        # List all chat files
        objects = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=prefix).get('Contents', [])
        
        # Normalize bank wallet for comparison
        bank_wallet_normalized = bank_wallet.strip().lower()
        
        for obj in objects:
            key = obj['Key']
            # Only process JSON files
            if key.endswith('.json'):
                # Extract the filename without path
                filename = key.split('/')[-1].replace('.json', '')
                wallets = filename.split('_')
                
                # Should have exactly 2 wallets in the filename
                if len(wallets) == 2:
                    # Normalize wallet addresses for comparison
                    wallet1 = wallets[0].lower()
                    wallet2 = wallets[1].lower()
                    
                    # Check if bank wallet is one of the participants
                    if bank_wallet_normalized in [wallet1, wallet2]:
                        # Find the other wallet in the chat
                        other_wallet = wallet2 if wallet1 == bank_wallet_normalized else wallet1
                        partners.add(other_wallet)
        
        # Get user names
        chat_partners = []
        for wallet in partners:
            profile = get_user_profile(wallet)
            if profile:
                chat_partners.append({
                    'wallet': wallet,
                    'name': profile['full_name']
                })
            else:
                # If no profile found, just show the wallet address
                chat_partners.append({
                    'wallet': wallet,
                    'name': wallet
                })
                
        return jsonify(chat_partners)
    
    except Exception as e:
        print(f"Error getting chat partners: {e}")
        traceback.print_exc()
        return jsonify([])

@app.route('/get-chat-messages', methods=['GET'])
def get_chat_messages():
    try:
        user_wallet = request.args.get('user', '').lower()
        bank_wallet = request.args.get('bank', '').lower()
        
        if not user_wallet or not bank_wallet:
            return jsonify(success=False, error="Missing wallet parameters"), 400
        
        # Create consistent chat file name
        participants = sorted([user_wallet, bank_wallet])
        chat_file = f"chats/{participants[0]}_{participants[1]}.json"
        
        try:
            response = s3.get_object(Bucket=BUCKET_NAME, Key=chat_file)
            chat_data = json.loads(response['Body'].read())
            return jsonify(success=True, messages=chat_data.get('messages', []))
        except s3.exceptions.NoSuchKey:
            # Create empty chat if doesn't exist
            s3.put_object(
                Bucket=BUCKET_NAME,
                Key=chat_file,
                Body=json.dumps({"messages": []}),
                ContentType='application/json'
            )
            return jsonify(success=True, messages=[])
        except Exception as e:
            print(f"Error loading chat: {e}")
            return jsonify(success=False, error="Failed to load chat"), 500
            
    except Exception as e:
        print(f"Error in get-chat-messages: {e}")
        return jsonify(success=False, error="Server error"), 500
    
@app.route('/send-chat-message', methods=['POST'])
def send_chat_message():
    try:
        data = request.json
        sender = data.get('sender', '').lower()
        receiver = data.get('receiver', '').lower()
        message = data.get('message', '')
        
        if not sender or not receiver or not message:
            return jsonify(success=False, error="Missing required fields"), 400
        
        # Create consistent chat file name
        participants = sorted([sender, receiver])
        chat_file = f"chats/{participants[0]}_{participants[1]}.json"
        
        # Try to load existing chat
        try:
            response = s3.get_object(Bucket=BUCKET_NAME, Key=chat_file)
            chat_data = json.loads(response['Body'].read())
        except s3.exceptions.NoSuchKey:
            chat_data = {"messages": []}
        
        # Add new message
        new_message = {
            "sender": sender,
            "receiver": receiver,
            "text": message,
            "timestamp": int(time.time())
        }
        chat_data['messages'].append(new_message)
        
        # Save back to S3
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=chat_file,
            Body=json.dumps(chat_data),
            ContentType='application/json'
        )
        
        return jsonify(success=True)
        
    except Exception as e:
        print(f"Error in send-chat-message: {e}")
        return jsonify(success=False, error="Failed to send message"), 500



@app.route('/get-pending-requests')
def get_pending_requests():
    bank_wallet = request.args.get('bank', '').strip()
    if not bank_wallet:
        return jsonify([])
    
    try:
        # Get directed loan requests
        prefix = f"loan_requests/{bank_wallet}/"
        objects = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=prefix).get('Contents', [])
        requests = []
        
        for obj in objects:
            response = s3.get_object(Bucket=BUCKET_NAME, Key=obj['Key'])
            request_data = json.loads(response['Body'].read())
            
            # Get user profile for name
            user_profile = get_user_profile(request_data['user_wallet'])
            if user_profile:
                request_data['name'] = user_profile['full_name']
                requests.append(request_data)
        
        return jsonify(requests)
    except Exception as e:
        print(f"Error getting pending requests: {e}")
        return jsonify([])

@app.route('/create-deal-from-request', methods=['POST'])
def create_deal_from_request():
    if not session.get('bank_logged_in'):
        return jsonify(success=False, message="Bank login required"), 401
        
    data = request.json
    user_wallet = data['user_wallet']
    request_key = data.get('request_key')  # Get the request key
    
    # Convert and validate values
    try:
        amount = int(data['amount'])
        duration = int(data['duration'])
        monthly = data['payment_type']
    except (ValueError, TypeError) as e:
        return jsonify(success=False, message=f"Invalid data format: {str(e)}"), 400

    # Validate values
    if amount <= 0 or duration <= 0:
        return jsonify(success=False, message="Amount and duration must be positive values"), 400

    # Calculate deadline (duration months from now)
    deadline = int(time.time()) + (duration * 30 * 24 * 3600)
    
    # Move loan request to active_loans BEFORE creating deal
    if request_key:
        bank_wallet = session['bank_wallet']
        if not move_loan_request_to_active_loans(bank_wallet, user_wallet, request_key):
            return jsonify(success=False, message="Failed to process loan request"), 500
    
    # Prepare blockchain transaction
    bank_wallet = session['bank_wallet']
    tx = contract.functions.createDeal(
        user_wallet,
        amount,
        deadline,
        monthly
    ).build_transaction({
        'chainId': w3.eth.chain_id,
        'gas': 500000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(bank_wallet),
        'from': bank_wallet
    })
    
    return jsonify({
        'success': True,
        'txData': {
            'from': bank_wallet,  # Add bank wallet as sender
            'to': CONTRACT_ADDRESS,
            'data': tx['data'],
            'value': '0x0',
            'gas': hex(tx['gas']),
            'gasPrice': hex(tx['gasPrice'])
        }
    })

@app.route('/reject-loan-request', methods=['POST'])
def reject_loan_request():
    if not session.get('bank_logged_in'):
        return jsonify(success=False, message="Bank login required"), 401
        
    data = request.json
    request_key = data.get('request_key')
    
    if not request_key:
        return jsonify(success=False, message="Missing request key"), 400
    
    try:
        # Delete the request from bucket
        s3.delete_object(Bucket=BUCKET_NAME, Key=request_key)
        return jsonify(success=True)
    except Exception as e:
        print(f"Error rejecting request: {e}")
        return jsonify(success=False, message=str(e)), 500

# Add this new route to app.py
@app.route('/get-approved-banks')
def get_approved_banks():
    """Get all approved banks from blockchain"""
    try:
        # Get all banks from the BankApproved event
        event_signature = w3.keccak(text="BankApproved(address)").hex()
        logs = w3.eth.get_logs({
            'fromBlock': 0,
            'toBlock': 'latest',
            'topics': [event_signature],
            'address': CONTRACT_ADDRESS
        })
        
        approved_banks = []
        for log in logs:
            # Extract bank address from the event
            address_bytes = log['topics'][1][-20:]
            wallet = Web3.to_checksum_address(address_bytes.hex())
            
            # Get bank profile
            profile = get_bank_profile(wallet)
            if profile:
                approved_banks.append({
                    'wallet': wallet,
                    'name': profile['name'],
                    'logo_cid': profile['logo_cid']
                })
                
        return jsonify(approved_banks)
    
    except Exception as e:
        print(f"Error getting approved banks: {e}")
        return jsonify([])


# app.py
@app.route('/accept-deal/<int:deal_id>', methods=['POST'])
def accept_deal(deal_id):
    if not session.get('user_logged_in'):
        return jsonify(success=False, message="User login required"), 401
        
    user_wallet = session['user_wallet']
    
    try:
        # Get deal details
        deal = contract.functions.loanDeals(deal_id).call()
        if deal[0].lower() != user_wallet.lower():
            return jsonify(success=False, message="Unauthorized access"), 403
            
        # Prepare transaction
        tx = contract.functions.acceptDeal(deal_id).build_transaction({
            'chainId': w3.eth.chain_id,
            'gas': 200000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(user_wallet),
            'from': user_wallet
        })
        
        return jsonify({
            'success': True,
            'txData': {
                'to': CONTRACT_ADDRESS,
                'data': tx['data'],
                'value': '0x0'
            }
        })
        
    except Exception as e:
        traceback.print_exc()
        return jsonify(success=False, message=f"Error: {str(e)}"), 500

# Update the approve_bank route
@app.route('/approve-bank/<wallet>')
def approve_bank(wallet):
    if not session.get('admin_logged_in'):
        flash("Admin access required", "danger")
        return redirect("/")
    
    try:
        # List all objects for this wallet
        objects = s3.list_objects_v2(Bucket=ADMIN_BUCKET, Prefix=f"{wallet}/")
        
        # Move each object
        for obj in objects.get('Contents', []):
            key = obj['Key']
            try:
                # Copy with retry
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        s3.copy_object(
                            Bucket=BANK_BUCKET,
                            Key=key,
                            CopySource={'Bucket': ADMIN_BUCKET, 'Key': key}
                        )
                        break
                    except ClientError:
                        if attempt < max_retries - 1:
                            time.sleep(2)
                        else:
                            raise
                
                # Delete original
                s3.delete_object(Bucket=ADMIN_BUCKET, Key=key)
                
            except ClientError as e:
                print(f"Error moving {key}: {e}")

        # Blockchain approval
        try:
            checksum_wallet = Web3.to_checksum_address(wallet)
            success = approve_bank_on_chain(checksum_wallet)  # Pass checksummed address
            if success:
                flash(f"Bank {wallet} approved successfully!", "success")
            else:
             flash("Blockchain approval failed. Check server logs.", "danger")
        except Exception as e:
             print(f"Blockchain error: {e}")
             flash(f"Blockchain approval failed: {str(e)}", "danger")
            
    except ClientError as e:
        print(f"Storage error: {e}")
        flash(f"Approval failed: {str(e)}", "danger")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/request-verification', methods=['POST'])
def request_verification():
    if not session.get('user_logged_in'):
        return jsonify(success=False, message="User login required"), 401
    
    user_wallet = session['user_wallet']
    
    try:
        # Get admin wallet from contract
        admin_wallet = contract.functions.admin().call()
        
        # Prepare blockchain transaction
        tx = contract.functions.requestVerification(
            Web3.to_checksum_address(admin_wallet)
        ).build_transaction({
            'chainId': w3.eth.chain_id,
            'gas': 200000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(user_wallet),
            'from': user_wallet
        })
        
        return jsonify({
            'success': True,
            'txData': {
                'from': user_wallet,  # ADD THIS LINE
                'to': CONTRACT_ADDRESS,
                'data': tx['data'],
                'value': '0x0'
            }
        })
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/admin-verification-action', methods=['POST'])
def admin_verification_action():
    if not session.get('admin_logged_in'):
        return jsonify(success=False, message="Admin access required"), 401

    data = request.json
    user_wallet = data.get('user_wallet')
    action = data.get('action')  # 'accept' or 'reject'
    
    try:
        if action == 'accept':
            # Prepare blockchain transaction
            tx = contract.functions.verifyUser(
                Web3.to_checksum_address(user_wallet)
            ).build_transaction({
                'chainId': w3.eth.chain_id,
                'gas': 200000,
                'gasPrice': w3.eth.gas_price,
                'nonce': w3.eth.get_transaction_count(ADMIN_WALLET),
            })
            
            return jsonify({
                'success': True,
                'txData': {
                    'from': ADMIN_WALLET,
                    'to': CONTRACT_ADDRESS,
                    'data': tx['data'],
                    'value': '0x0',
                    'gas': hex(tx['gas']),
                    'gasPrice': hex(tx['gasPrice'])
                }
            })
            
        elif action == 'reject':
            # Handle rejection off-chain
            # (Add any necessary off-chain logic here)
            return jsonify(success=True)
            
        else:
            return jsonify(success=False, message="Invalid action"), 400
            
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/verify-user/<user_wallet>')
def verify_user(user_wallet):
    # Check if admin or bank is logged in
    if not (session.get('admin_logged_in') or session.get('bank_logged_in')):
        flash("Access denied", "danger")
        return redirect("/")
    
    if verify_user(user_wallet):
        flash("User verified", "success")
    else:
        flash("Verification failed", "danger")
    
    return redirect(url_for('view_profile', wallet=user_wallet))

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in') or session.get('admin_wallet') != ADMIN_WALLET:
        return redirect(url_for('index'))
    
    admin_wallet_addr = session.get('admin_wallet', ADMIN_WALLET)
    
    # Get all profiles from buckets
    pending_banks = []
    bank_profiles = []
    user_profiles = []
    
    try:
        # Scan ALL blocks for UserProfileCreated events
        event_signature = w3.keccak(text="UserProfileCreated(address)").hex()
        logs = w3.eth.get_logs({
            'fromBlock': 0,  # Start from genesis block
            'toBlock': 'latest',
            'topics': [event_signature],
            'address': CONTRACT_ADDRESS
        })
        
        # Process all user creation events
        user_wallets = set()
        for log in logs:
            try:
                address_bytes = log['topics'][1][-20:]
                wallet = Web3.to_checksum_address(address_bytes.hex())
                user_wallets.add(wallet)
            except Exception as e:
                print(f"Error processing log: {e}")
        
        # Fetch profiles for all detected users
        for wallet in user_wallets:
            try:
                profile = get_user_profile(wallet)
                if profile:
                    user_profiles.append({
                        'full_name': profile['full_name'],
                        'wallet': wallet,
                        'verification_status': profile['verification_status']
                    })
            except Exception as e:
                print(f"Error loading user {wallet}: {e}")
                
    except Exception as e:
        flash(f'Error loading user profiles: {str(e)}', 'danger')
        traceback.print_exc()

    try:
        # We'll get the latest 5000 blocks to search for UserProfileCreated events
        latest_block = w3.eth.block_number
        from_block = max(0, latest_block - 5000)
        
        # Create event filter for UserProfileCreated
        event_signature = w3.keccak(text="UserProfileCreated(address)").hex()
        event_filter = {
            'fromBlock': from_block,
            'toBlock': latest_block,
            'topics': [event_signature]
        }
        
        # Get logs
        logs = w3.eth.get_logs(event_filter)
        
        # Process each user profile
        for log in logs:
            try:
                # Extract wallet address from event data
                wallet = '0x' + log['topics'][1].hex()[-40:]
                checksum_wallet = Web3.to_checksum_address(wallet)
                
                # Get user profile from blockchain
                profile = get_user_profile(checksum_wallet)
                if profile:
                    user_profiles.append({
                        'full_name': profile['full_name'],
                        'wallet': checksum_wallet,
                        'verification_status': profile['verification_status']
                    })
            except Exception as e:
                print(f"Error processing user profile for {wallet}: {e}")
                traceback.print_exc()
                
    except Exception as e:
        flash(f'Error loading user profiles from blockchain: {str(e)}', 'danger')
        traceback.print_exc()
    # Fetch pending bank profiles from ADMIN_BUCKET
    try:
        pending_objects = s3.list_objects_v2(Bucket=ADMIN_BUCKET).get('Contents', [])
        for obj in pending_objects:
            if obj['Key'].endswith('metadata.json'):
                response = s3.get_object(Bucket=ADMIN_BUCKET, Key=obj['Key'])
                profile = json.loads(response['Body'].read())
                
                # Only process bank profiles
                if profile.get('profile_type') == "bank":
                    wallet = obj['Key'].split('/')[0]
                    profile['wallet'] = wallet
                    profile['key'] = obj['Key']
                    
                    # Add formatted date
                    if 'timestamp' in profile:
                        dt = datetime.fromtimestamp(profile['timestamp'])
                        profile['formatted_date'] = dt.strftime('%Y-%m-%d')
                    else:
                        profile['formatted_date'] = 'N/A'
                    
                    pending_banks.append(profile)
    except Exception as e:
        flash(f'Error loading pending banks: {str(e)}', 'danger')
    
    # Fetch approved bank profiles from BANK_BUCKET
    try:
        bank_objects = s3.list_objects_v2(Bucket=BANK_BUCKET).get('Contents', [])
        for obj in bank_objects:
            if obj['Key'].endswith('metadata.json'):
                response = s3.get_object(Bucket=BANK_BUCKET, Key=obj['Key'])
                profile = json.loads(response['Body'].read())
                
                # Only process bank profiles
                if profile.get('profile_type') == "bank":
                    wallet = obj['Key'].split('/')[0]
                    profile['wallet'] = wallet
                    profile['key'] = obj['Key']
                    
                    if 'timestamp' in profile:
                        dt = datetime.fromtimestamp(profile['timestamp'])
                        profile['formatted_date'] = dt.strftime('%Y-%m-%d')
                    else:
                        profile['formatted_date'] = 'N/A'
                    
                    bank_profiles.append(profile)
    except Exception as e:
        flash(f'Error loading approved banks: {str(e)}', 'danger')
    
    
    try:
        total_users = get_total_users()
    except Exception as e:
        print(f"Error getting user count from blockchain: {e}")
        total_users = len(user_profiles)  # Fallback to S3 count
    # Stats for dashboard
    stats = {
        'total_profiles': total_users + len(bank_profiles) + len(pending_banks),
        'total_users': total_users,  # Use blockchain count
        'total_banks': len(bank_profiles),
        'pending_approvals': len(pending_banks)
    }
    pending_verifications = []
    for user in user_profiles:
        if user['verification_status'] == 1:  # Pending status
            pending_verifications.append({
                'wallet': user['wallet'],
                'name': user['full_name']
            })
    
    return render_template('admin_dashboard.html', 
                           pending_banks=pending_banks,
                           bank_profiles=bank_profiles,
                           user_profiles=user_profiles,
                           pending_verifications=pending_verifications,
                           stats=stats,
                           admin_wallet=admin_wallet_addr,
                           gateway_url=GATEWAY_URL)


@app.route('/admin-status')
def admin_status():
    contract_admin = contract.functions.admin().call()
    return jsonify({
        'env_admin': ADMIN_WALLET,
        'contract_admin': contract_admin,
        'match': contract_admin.lower() == ADMIN_WALLET.lower()
    })

@app.route('/create-directed-loan-request', methods=['POST'])
def create_directed_loan_request():
    if not session.get('user_logged_in'):
        return jsonify(success=False, error="User login required"), 401

    data = request.json
    bank_wallet = data.get('bank_wallet')
    bank_wallet = bank_wallet.strip().lower()
    amount = data.get('amount')
    duration = data.get('duration')
    payment_type = data.get('payment_type')

    # Validate
    if not bank_wallet or not amount or not duration or not payment_type:
        return jsonify(success=False, error="Missing required fields"), 400

    # Create loan request object
    loan_request = {
        'user_wallet': session['user_wallet'],
        'bank_wallet': bank_wallet,
        'amount': amount,
        'duration': duration,
        'payment_type': payment_type,
        'timestamp': int(time.time()),
        'status': 'pending'
    }

    # Create a unique key for the loan request
    key = f"loan_requests/{bank_wallet}/{session['user_wallet']}_{int(time.time())}.json"

    try:
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=key,
            Body=json.dumps(loan_request),
            ContentType='application/json'
        )
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500

# Change this route
@app.route('/create-loan-request', methods=['POST'])
def create_loan_request():
    if not session.get('user_logged_in'):
        return jsonify(success=False, message="User login required"), 401
        
    data = request.get_json()
    user_wallet = session['user_wallet']  # Use session wallet instead of request data
    amount = int(data.get('amount'))
    duration = int(data.get('duration'))
    monthly = data.get('payment_type') == 'monthly'
    
    try:
        # Prepare blockchain transaction
        tx = contract.functions.createLoanRequest(amount, duration, monthly).build_transaction({
            'chainId': w3.eth.chain_id,
            'gas': 300000,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(user_wallet),
            'from': user_wallet
        })
        
        return jsonify({
            'success': True,
            'txData': {
                'from': user_wallet,
                'to': CONTRACT_ADDRESS,
                'data': tx['data'],
                'value': '0x0'
            }
        })
        
    except Exception as e:
        traceback.print_exc()
        return jsonify(success=False, message=f"Error creating transaction: {str(e)}"), 500

@app.route('/create-deal', methods=['POST'])
def create_deal():
    if not session.get('bank_logged_in'):
        return jsonify(success=False, message="Bank login required"), 401
        
    bank_wallet = session['bank_wallet']
    user_wallet = request.form.get('user_wallet')
    amount = int(request.form.get('amount'))
    
    # Convert timestamp string to integer
    deadline_timestamp = int(request.form.get('deadline'))
    
    monthly = request.form.get('payment_type') == 'monthly'
    
    # Prepare blockchain transaction
    tx = contract.functions.createDeal(
        user_wallet,
        amount,
        deadline_timestamp,  # Use timestamp directly
        monthly
    ).build_transaction({
        'chainId': w3.eth.chain_id,
        'gas': 500000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(bank_wallet),
        'from': bank_wallet
    })
    
    return jsonify({
        'success': True,
        'txData': {
            'to': CONTRACT_ADDRESS,
            'data': tx['data'],
            'value': '0x0'
        }
    })

@app.route('/search-loan-requests')
def search_loan_requests():
    query = request.args.get('q', '').lower()
    bank_wallet = request.args.get('bank', '').lower()  # Get bank wallet from query params
    results = []
    
    # Get all users from blockchain
    all_users = get_all_users()
    
    # Filter by query and check loan requests
    for user in all_users:
        try:
            # Get loan request from blockchain
            request_data = contract.functions.loanRequests(user).call()
            # Check if active loan request exists
            if request_data[4]:  # active field is True
                # Get user profile for name matching
                user_profile = get_user_profile(user)
                if user_profile:
                    # Check if query matches name or wallet
                    if query in user_profile['full_name'].lower() or query in user.lower():
                        results.append({
                            'user': user,
                            'name': user_profile['full_name'],
                            'amount': request_data[1],
                            'duration': request_data[2],
                            'monthly': request_data[3]
                        })
        except Exception as e:
            print(f"Error processing user {user}: {e}")
            continue

    # Add directed loan requests from Filebase
    try:
        prefix = "loan_requests/"
        objects = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=prefix).get('Contents', [])
        for obj in objects:
            if bank_wallet.lower() in obj['Key'].lower():
                response = s3.get_object(Bucket=BUCKET_NAME, Key=obj['Key'])
                directed_request = json.loads(response['Body'].read())
                
                # Get user profile
                user_profile = get_user_profile(directed_request['user_wallet'])
                if user_profile:
                    # Check if query matches
                    if (query in user_profile['full_name'].lower() or 
                        query in directed_request['user_wallet'].lower()):
                        results.append({
                            'user': directed_request['user_wallet'],
                            'name': user_profile['full_name'],
                            'amount': directed_request['amount'],
                            'duration': directed_request['duration'],
                            'monthly': directed_request['payment_type'] == 'monthly'
                        })
    except Exception as e:
        print(f"Error fetching directed requests: {e}")
    
    return jsonify(results)

@app.route('/get-directed-loan-requests')
def get_directed_loan_requests():
    bank_wallet = request.args.get('bank', '').strip()
    if not bank_wallet:
        return jsonify([])
    
    prefix = f"loan_requests/{bank_wallet}/"
    try:
        objects = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=prefix).get('Contents', [])
        requests = []
        
        for obj in objects:
            response = s3.get_object(Bucket=BUCKET_NAME, Key=obj['Key'])
            request_data = json.loads(response['Body'].read())
            
            # Get user profile for name
            user_profile = get_user_profile(request_data['user_wallet'])
            if user_profile:
                request_data['name'] = user_profile['full_name']
            
            requests.append(request_data)
        
        return jsonify(requests)
    except Exception as e:
        print(f"Error getting directed loan requests: {e}")
        return jsonify([])
@app.route('/submit-rating', methods=['POST'])
def submit_rating():
    if not session.get('bank_logged_in'):
        return jsonify(success=False, error="Bank login required"), 401

    try:
        # Get data from request
        data = request.get_json()
        if not data:
            return jsonify(success=False, error="No data provided"), 400

        # Extract parameters with fallbacks
        deal_id = data.get('deal_id', 'N/A')
        user_wallet = data.get('user_wallet', '').strip().lower()
        stars = data.get('stars', 0)
        comment = data.get('comment', '')
        
        if not user_wallet:
            return jsonify(success=False, error="Missing user wallet"), 400

        bank_wallet = session['bank_wallet']
        
        # Create rating object
        rating = {
            'deal_id': deal_id,
            'bank_wallet': bank_wallet,
            'stars': stars,
            'comment': comment,
            'timestamp': int(time.time())
        }
        
        # Create unique key for the rating
        key = f"{user_wallet}/ratings/{bank_wallet}_{int(time.time())}.json"
        
        # Save to Filebase
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=key,
            Body=json.dumps(rating),
            ContentType='application/json'
        )
        
        return jsonify(success=True)
        
    except Exception as e:
        print(f"Error submitting rating: {str(e)}")
        traceback.print_exc()
        return jsonify(success=False, error=str(e)), 500

@app.route('/adminlogout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_wallet', None)
    flash("Admin logged out", "success")
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)