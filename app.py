from flask import Flask, jsonify, request, session, redirect, url_for, render_template, flash
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from datetime import timedelta
from web3 import Web3
import os
import json
from dotenv import load_dotenv
from app.models import User  # Assuming you have a User model for authentication
from app.routes import main
from config import Config


# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config.from_object(Config)

app.register_blueprint(main)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app.register_blueprint(main)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Load environment variables
load_dotenv()

# Blockchain Integration
infura_url = f"https://sepolia.infura.io/v3/{os.getenv('PROJECT_ID')}"
web3 = Web3(Web3.HTTPProvider(infura_url))

# Replace with your deployed contract address and ABI file
contract_address = '0x5874121c17c1662203Ae071B8e726aCB77c5014F'
with open('build/contracts/PatientRecords.json', 'r') as file:
    contract_json = json.load(file)
contract_abi = contract_json['abi']

# Create a contract instance
contract = web3.eth.contract(address=contract_address, abi=contract_abi)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        city = request.form.get('city')

        if not username or not password or not city:
            flash('Please fill in all fields', 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['city'] = city
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('patient_dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Patient dashboard route
@app.route('/patient_dashboard')
@login_required
def patient_dashboard():
    city = session.get('city', 'Unknown')
    return render_template('patient_dashboard.html', city=city)

# Route to add a new patient record
@app.route('/addRecord', methods=['POST'])
@login_required
def add_record():
    data = request.json
    patient_name = data.get('patientName')
    diagnosis = data.get('diagnosis')
    treatment = data.get('treatment')

    if current_user.is_authenticated:
        user_address = current_user.wallet_address
        
        try:
            transaction = contract.functions.addRecord(patient_name, diagnosis, treatment).transact({
                'from': user_address,
                'gas': 3000000
            })
            tx_receipt = web3.eth.waitForTransactionReceipt(transaction)
            return jsonify({'status': 'Record added', 'txHash': tx_receipt.transactionHash.hex()}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'User not authenticated'}), 401

# Route to get patient records
@app.route('/getRecords', methods=['GET'])
@login_required
def get_records():
    patient_address = request.args.get('address')

    try:
        records = contract.functions.getRecords(patient_address).call()
        return jsonify({'records': records}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500



if __name__ == "__main__":
    app.run(debug=True)
