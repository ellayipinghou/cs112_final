import os
import requests
from flask import Flask, request, jsonify, abort

##Global Variables Section
# Rocket.Chat Credentials
ROCKET_CHAT_URL = "https://chat.genaiconnect.net"
ROCKET_USER_ID = os.environ.get("RCuser")
ROCKET_AUTH_TOKEN = os.environ.get("RCtoken")

# File temporary section
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def download_file(file_id, filename):
    """Download file from Rocket.Chat and save locally."""

    if allowed_file(filename):
        file_url = f"{ROCKET_CHAT_URL}/file-upload/{file_id}/{filename}"
        headers = {
            "X-User-Id": ROCKET_USER_ID,
            "X-Auth-Token": ROCKET_AUTH_TOKEN
        }

        response = requests.get(file_url, headers=headers, stream=True)
        if response.status_code == 200:
            local_path = os.path.join(UPLOAD_FOLDER, filename)
            with open(local_path, "wb") as file:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)
            return local_path
    
    print(f"INFO - some issue with {filename} with {response.status_code} code")
    return None

def send_message_with_file(room_id, message, file_path):
    """Send a message with the downloaded file back to the chat."""
    url = f"{ROCKET_CHAT_URL}/api/v1/rooms.upload/{room_id}"
    headers = {
        "X-User-Id": ROCKET_USER_ID,
        "X-Auth-Token": ROCKET_AUTH_TOKEN
    }
    files = {"file": (os.path.basename(file_path), open(file_path, "rb"))}
    data = {"msg": message}

    response = requests.post(url, headers=headers, files=files, data=data)
    if response.status_code != 200:
        return {"error": f"Failed to upload file, Status Code: {response.status_code}, Response: {response.text}"}
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        return {"error": "Invalid JSON response from Rocket.Chat API", "raw_response": response.text}
    
# App settings
app = Flask(__name__)


@app.route('/', methods=['POST'])
def hello_world():
   return 'Hello from Koyeb - you reached the main page!'

@app.route('/query', methods=['POST'])
def main():
    data = request.get_json() 

    print(f"full request : {data}")

    if (not data) and ("text" not in data) and ("message" not in data) and ("files" not in data["message"]):
        return jsonify({"error": "Invalid request format"}), 400
    
    user = data.get("user_name", "Unknown")
    room_id = data.get("channel_id", "")

    # A file is sent by the user
    if ("message" in data) and ('file' in data['message']):
        print(f"INFO - detected file")
        saved_files = []

        for file_info in data["message"]["files"]:
            file_id = file_info["_id"]
            filename = file_info["name"]

            # Download file
            file_path = download_file(file_id, filename)

            if file_path:
                saved_files.append(file_path)
            else:
                return jsonify({"error": "Failed to download file"}), 500
        
        # Send message with the downloaded file
        message_text = f"File uploaded by {user}"
        for saved_file in saved_files:
            send_message_with_file(room_id, message_text, saved_file)

        return jsonify({"text": "Files processed and re-sent successfully!"})

    # Text message is sent by the user
    elif ("text" in data):
        print(f"INFO - text msg detected")

        # Extract relevant information
        message = data.get("text", "")

        # Ignore bot messages
        if data.get("bot") or not message:
            return jsonify({"status": "ignored"})

        print(f"Message from {user} : {message}")
            
        response = {
                    "text": message,
            }
        return jsonify(response)
    else:
        print(f"ERROR - unsupported message type")
        abort(404)
    
@app.errorhandler(404)
def page_not_found(e):
    return "Not Found", 404

if __name__ == "__main__":
    app.run()