from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from llmproxy import generate, text_upload, retrieve
from urllib.parse import urlparse

app = Flask(__name__)

# Add CORS headers to all responses
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Client-FD'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

# Dictionary mapping client_fd to their current page URL
current_page_urls = {} 

# Run llm data transfer route to port 9450
@app.route('/upload_html', methods=['POST'])
def process():
    html = request.data.decode('utf-8', errors='ignore')
    if not html:
        return jsonify({"error": "No HTML content"}), 400
    
    soup = BeautifulSoup(html, 'html.parser')
    
    # Extract page title and description
    title = soup.find('title')
    title_text = title.get_text(strip=True) if title else "Unknown"
    
    meta_desc = soup.find('meta', attrs={'name': 'description'})
    description_text = meta_desc.get('content', '') if meta_desc else ""

    # Remove scripts, styles, navigation, etc.
    for tag in soup(['script', 'style', 'nav', 'header', 'footer']):
        tag.decompose()

    # Focus on main content
    main_content = soup.find('main') or soup.find('article') or soup.find(id='content') or soup.body
    
    text = (main_content or soup).get_text(separator='\n', strip=True)
    
    # Remove excessive whitespace
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    cleaned_text = '\n'.join(lines)
    
    # Prepend metadata for better context
    context_with_metadata = f"Page Title: {title_text}\n"
    if description_text:
        context_with_metadata += f"Page Description: {description_text}\n"
    context_with_metadata += f"\nPage Content:\n{cleaned_text}"
    
    print(f"Cleaned text (first 500 chars): {context_with_metadata[:500]}")
    
    client_fd = request.headers.get('Client-FD', 'unknown')
    page_url = request.headers.get('Page-URL', 'unknown')
    
    print(f"DEBUG: Received Page-URL header: '{page_url}'")

    # Handle missing/invalid URL
    if not page_url or page_url == 'unknown' or page_url == '(null)':
        print("WARNING: Invalid Page-URL, using fallback")
        clean_url = f"unknown_page_{client_fd}"
    else:
        try:
            parsed = urlparse(page_url)
            if parsed.netloc:
                if parsed.path and parsed.path != '/':
                    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                else:
                    clean_url = f"{parsed.scheme}://{parsed.netloc}"
            else:
                print(f"WARNING: Could not parse URL '{page_url}'")
                clean_url = f"unknown_page_{client_fd}"
        except Exception as e:
            print(f"ERROR parsing URL: {e}")
            clean_url = f"unknown_page_{client_fd}"
    
    print(f"DEBUG: Clean URL: '{clean_url}'")
    
    page_session_id = f"page_{clean_url}"
    current_page_urls[client_fd] = clean_url

    print(f"DEBUG UPLOAD: page_session_id={page_session_id}, client_fd={client_fd}, html_length={len(html)}")

    # Upload with metadata included
    response = text_upload(
        text=context_with_metadata,  # Use version with metadata
        strategy='smart', 
        session_id=page_session_id, 
        description=f'Content from webpage: {clean_url} (Title: {title_text})'
    )

    print(f"DEBUG UPLOAD RESPONSE: {response}")

    return jsonify({"status": "success", "response": response})
    
@app.route('/query', methods=['POST'])
def query():
    data = request.get_json()
    if not data or "query" not in data:
        return jsonify({"error": "Missing 'query' field"}), 400

    user_query = data["query"]

    client_fd = request.headers.get('Client-FD', 'unknown')

    # retrieve from most recent PAGE session (not conversation session)
    page_url = current_page_urls.get(client_fd, "unknown")

    if page_url == "unknown":
        return jsonify({"text": "No page loaded yet. Please navigate to a webpage first."})
    
    # Use URL-based session ID
    page_session_id = f"page_{page_url}"
    
    print(f"DEBUG: Using page_session_id={page_session_id} for client_fd={client_fd}")

    print(f"DEBUG: Query for session_id={page_session_id}, client_fd={client_fd}")

    # retrieve relevant chunks from the session
    context_chunks = retrieve(
        query=user_query,
        session_id=page_session_id,
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
    
    # Use CONVERSATION session for generate (maintains chat history)
    conv_session_id = f"chat_{client_fd}"
    
    response = generate(
        model='4o-mini',
        system="You are a helpful assistant answering questions about a webpage. Answer the user's questions, using the provided context from the page if relevant.",
        query=f"Page content:\n{context_text}\n\nUser question: {user_query}",
        temperature=0.0,
        lastk=5,  # Include last 5 messages for conversational context
        session_id=conv_session_id,  # Separate conversation session
    )

    print(response["response"])

    return jsonify({"text": response["response"]})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9450)
