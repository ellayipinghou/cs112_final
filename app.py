from typing import Optional, Union, List, Dict, Any

from flask import Flask, request, jsonify
from llmproxy import generate, text_upload, retrieve

app = Flask(__name__)

#run llm data transfer route to port 9450
@app.route('/upload_html', methods=['POST'])
def process():
    # get HTML directly from body (not JSON)
    html = request.data.decode('utf-8', errors='ignore')

    # data = request.get_json() 
    # if not data or "html" not in data:
    #     return jsonify({"error": "Invalid request format"}), 400
    
    # html = data["html"]
    
    if not html:
        return jsonify({"error": "No HTML content"}), 400
    
    client_fd = request.headers.get('Client-FD', 'unknown')
    session_id = f"client_{client_fd}"

    # llm does stuff
    response = text_upload(text=html, strategy='smart', session_id=session_id, description='HTML page')

    print(response)

    return jsonify({"status": "success", "response": response})
    
@app.route('/query', methods=['POST'])
def query():
    data = request.get_json()
    if not data or "query" not in data:
        return jsonify({"error": "Missing 'query' field"}), 400

    user_query = data["query"]

    client_fd = request.headers.get('Client-FD', 'unknown')
    session_id = f"client_{client_fd}"

    # retrieve relevant chunks from the session
    context_chunks = retrieve(
        query=user_query,
        session_id=session_id,
        rag_threshold=0.1,  # lower threshold = more inclusive
        rag_k=5  # get top 5 relevant chunks
    )

    # combine chunks into a single prompt
    context_text = ""
    for chunk in context_chunks:
        for c in chunk["chunks"]:
            context_text += c + "\n"

    prompt = f"Use the following HTML content to answer the question:\n{context_text}\nQuestion: {user_query}"

    # call generate with the context
    response = generate(
        model='4o-mini',
        system="Answer based on the provided HTML content. Ignore styling/scripts. If there are multiple HTML pages uploaded to the session and the user does not specify which they are talking about in the query, use the most recent one.",
        query=prompt,
        temperature=0.0,
        lastk=0,
        session_id=session_id
    )

    print(response["response"])

    return jsonify({"text": response["response"]})

# curl -X POST http://127.0.0.1:9450/upload_html      -H "Content-Type: application/json"      -d '{"html": "<html><body><h1>Hello from curl</h1></body></html>"}'

# curl -X POST http://127.0.0.1:9450/query -H "Content-Type: application/json" -d '{"query": "summarize the HTML of this page"}'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9450)

