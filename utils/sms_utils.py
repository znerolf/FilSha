import os
import requests
import random

# Function to send SMS
def send_sms(phone_number, message):
    username = os.getenv('SMS_USERNAME')
    password = os.getenv('SMS_PASSWORD')
    url = os.getenv('SMS_API_URL')
    
    # Use the correct payload structure
    payload = {
        "message": message,
        "phoneNumbers": [phone_number]
    }
    
    # Set the correct headers
    headers = {"Content-Type": "application/json"}
    
    try:
        # Send the request with JSON payload and authentication     
        response = requests.post(url, json=payload, headers=headers, auth=(username, password))
        
        # Log the response for debugging
        print(f"SMS API Response: {response.status_code}, {response.text}")
        
        # Check for successful response
        if response.status_code in [200, 201, 202]:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error sending SMS: {e}")
        return False


def generate_otp():
    return ''.join(random.choice('0123456789') for _ in range(6))

def send_otp_via_sms(phone_number, otp):
    message = f"🔐 Your Filsha OTP Verification Code: {otp}\n\nUse this code to complete your login. This code expires in 10 minutes.\n\nDo not share this code with anyone."
    return send_sms(phone_number, message)