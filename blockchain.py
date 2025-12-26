from web3 import Web3
import json
import os
from dotenv import load_dotenv

load_dotenv()

private_key = os.getenv("PRIVATE_KEY")

# Connect to Ganache or any other blockchain
ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

# Load the contract ABI and contract address
contract_address = '0x1A6Cbea6c0e1792e2dbe3d552FfCAE3DF034df27'
with open('build/contracts/PatientRecords.json') as f:
    contract_json = json.load(f)
    contract_abi = contract_json['abi']

contract = web3.eth.contract(address=contract_address, abi=contract_abi)

def send_prescription_transaction(account, patient_id, doctor_id, prescription_data):
    tx = contract.functions.storePrescription(patient_id, doctor_id, prescription_data).build_transaction({
        'from': account,
        'gas': 100000,
        'gasPrice': web3.to_wei('0.5', 'gwei'),  # Lower the gas price
        'nonce': web3.eth.get_transaction_count(account),
    })
    signed_tx = web3.eth.account.sign_transaction(tx, private_key=private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    web3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_hash.hex()

def get_prescription(patient_id):
    prescription_data = contract.functions.getPrescription(patient_id).call()
    return prescription_data

if __name__ == "__main__":
    # Check if private key is loaded
    if not private_key:
        print("Private key is missing. Please add it to the .env file.")
        exit()

    account = web3.eth.account.from_key(private_key).address

    # Example transaction to add a prescription
    # Example transaction to add a prescription
    print("Storing a prescription...")
    tx_hash = send_prescription_transaction(account, 1, 101, "Paracetamol 500mg")
    print(f"Transaction Hash: {tx_hash}")


    # Retrieve and verify the stored prescription
    print("Retrieving the prescription...")
    stored_data = get_prescription(1)
    print(f"Stored Prescription Data: {stored_data}")