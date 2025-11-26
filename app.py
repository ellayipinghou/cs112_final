from typing import Optional, Union, List, Dict, Any
from bs4 import BeautifulSoup
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
    
    # HTML parser
    soup = BeautifulSoup(html, 'html.parser')

    # Remove scripts, styles, navigation, etc.
    for tag in soup(['script', 'style', 'nav', 'header', 'footer', 'aside']):
        tag.decompose()

    # Get main content text
    text = soup.get_text(separator='\n', strip=True)
    
    # Remove excessive whitespace
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    cleaned_text = '\n'.join(lines)
    
    # get text
    print(f"Cleaned text: {cleaned_text}")
    
    client_fd = request.headers.get('Client-FD', 'unknown')
    session_id = f"client_{client_fd}"

    print(f"DEBUG UPLOAD: session_id={session_id}, client_fd={client_fd}, html_length={len(html)}")

    # llm does stuff
    response = text_upload(text=cleaned_text, strategy='smart', session_id=session_id, description='Text of HTML page')

    print(f"DEBUG UPLOAD RESPONSE: {response}")

    return jsonify({"status": "success", "response": response})
    
@app.route('/query', methods=['POST'])
def query():
    data = request.get_json()
    if not data or "query" not in data:
        return jsonify({"error": "Missing 'query' field"}), 400

    user_query = data["query"]

    client_fd = request.headers.get('Client-FD', 'unknown')
    session_id = f"client_{client_fd}"

    print(f"DEBUG: Query for session_id={session_id}, client_fd={client_fd}")

    # retrieve relevant chunks from the session
    context_chunks = retrieve(
        query=user_query,
        session_id=session_id,
        rag_threshold=0.1,  # lower threshold = more inclusive
        rag_k=5  # get top 5 relevant chunks
    )

    if not context_chunks:
        print("DEBUG: No chunks retrieved!")
        return jsonify({"text": "Your document is still being processed. Please try your query again shortly."})

    # combine chunks into a single prompt
    context_text = ""
    for chunk in context_chunks:
        if isinstance(chunk, dict) and "chunks" in chunk:
            for c in chunk["chunks"]:
                context_text += str(c) + "\n"

    print(f"DEBUG: Final context_text length: {len(context_text)}")
    print(f"DEBUG: Context preview: {context_text[:500]}")

    if not context_text.strip():
        return jsonify({"text": "No context found. Document may still be processing."})
    
    prompt = f"Context:\n{context_text}\n\nQuestion: {user_query}"

    # call generate with the context
    response = generate(
        model='4o-mini',
        system="You will receive the text of an HTML page. Answer user queries based on it. If no context is found, inform the user.",
        query=prompt,
        temperature=0.0,
        lastk=0,
        session_id=session_id
    )

    print(response["response"])

    return jsonify({"text": response["response"]})

# curl -X POST http://127.0.0.1:9450/upload_html      -H "Content-Type: application/json"      -d '{"html": "<html><body><h1>Hello from curl</h1></body></html>"}'

# curl -X POST http://127.0.0.1:9450/query -H "Content-Type: application/json" -H "Client-FD: 123" -d '{"query": "summarize the page in one paragraph, at a fifth grade level"}'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9450)
