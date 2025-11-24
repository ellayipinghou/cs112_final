from flask import Flask, request, jsonify
from llmproxy import generate, end_point, api_key

app = Flask(__name__)

@app.route('/', methods=['POST'])
def hello_world():
   return 'Hello from Koyeb - you reached the main page!'

@app.route('/query', methods=['POST'])
def main():
    data = request.get_json() 

    # Extract relevant information
    user = data.get("user_name", "Unknown")
    message = data.get("text", "")

    # Ignore bot messages
    if data.get("bot") or not message:
        return jsonify({"status": "ignored"})

    print(f"Message from {user} : {message}")

    if message == "yes_clicked": #respond with a button for possible further interaction
        response = {
                    "attachments": [
                            {
                            "text": "You have selected: ✅ Yes!",
                            "actions": [
                                {
                                "type": "button",
                                "text": "Thanks for the feedback 😃",
                                "msg": "post_yes_clicked",
                                "msg_in_chat_window": True,
                                "msg_processing_type": "sendMessage"
                                }
                            ]
                            }
                        ]
                    }
    elif message == "no_clicked": # respond with a text
        response = {
                    "text": "You have selected: ❌ No! Sorry to hear that 😔, Please tell us why?"
        }
    else:
        #Generate a response (you can integrate with AI/chatbot here)
        response_text = generate(
            model='4o-mini',
            system='answer my question and tell me related topics',
            query= message,
            temperature=0.0,
            lastk=0,
            session_id='GenericSession'
        )
        
        response = {
                    "text": response_text,
                    "attachments": [
                        {
                            "title": "User Options",
                            "text": "Are you happy with the response?",
                            "actions": [
                                {
                                    "type": "button",
                                    "text": "✅ Yes",
                                    "msg": "yes_clicked",
                                    "msg_in_chat_window": True,
                                    "msg_processing_type": "sendMessage",
                                    "button_id": "yes_button"
                                },
                                {
                                    "type": "button",
                                    "text": "❌ No",
                                    "msg": "no_clicked",
                                    "msg_in_chat_window": True,
                                    "msg_processing_type": "sendMessage"
                                }
                            ]
                        }
                    ]
        }
    return jsonify(response)
    
@app.errorhandler(404)
def page_not_found(e):
    return "Not Found", 404

if __name__ == "__main__":
    app.run()