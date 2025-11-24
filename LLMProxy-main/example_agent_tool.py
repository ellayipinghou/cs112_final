from llmproxy import generate


# Extracts the tool from text using regex
def extract_tool(text):
    import re

    match = re.search(r'websearch\([^)]*\)', text)
    if match:
        return match.group() 
    

    match = re.search(r'get_page\([^)]*\)', text)
    if match:
        return match.group() 


    match = re.search(r'send_email\([^)]*\)', text)
    if match:
        return match.group() 

    return


# Tool to send an email
# This has been written based on the Tufts EECS email infrastructure
# Can be modified for other email clients (e.g., gmail, yahoo)
def send_email(src, dst, subject, content):

    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import json
 
    # Email configuration
    smtp_server = "smtp-tls.eecs.tufts.edu"  # e.g., mail.yourdomain.com
    smtp_port = 587  # Usually 587 for TLS, 465 for SSL
    sender_email = src
    receiver_email = dst


    # Add email password to config.json
    with open('config.json', 'r') as file:
        config = json.load(file)

    password = config['password']

    # Create the email message
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject

    body = content
    msg.attach(MIMEText(body, "plain"))

    # Send email
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection (use only if the server supports TLS)
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        return "Email sent successfully!"
    except Exception as e:
        return f"Error: {e}" 


# Tool to return the webpage based on URL
def get_page(url):

    import requests
    from bs4 import BeautifulSoup


    headers = {"User-Agent": "Mozilla/5.0"}  # Helps avoid bot detection
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Extracting the main content (removing scripts, styles, and ads)
        for unwanted in soup(["script", "style", "header", "footer", "nav", "aside"]):
            unwanted.extract()  # Remove these elements

        text = soup.get_text(separator=" ", strip=True)  # Extract clean text

        # Limit length to avoid very long output
        clean_text = " ".join(text.split())  # First 500 words
        return clean_text
        
    else:
        return f"Failed to fetch {url}, status code: {response.status_code}"


# Tool to perform a websearch using duckduckgo
def websearch(query):
    from duckduckgo_search import DDGS

    # Initialize the search client
    with DDGS() as ddgs:
        results = list(ddgs.text(query, max_results=5))

    return [result["href"] for result in results]


# agent program to handle user requests
def agent_email(query):
    
    system = """
    You are an AI agent designed to handle user requests.
    In addition to your own intelligence, you are given access to a set of tools.

    Think step-by-step, breaking down the task into a sequence small steps.

    If you can't resolve the query based on your intelligence, ask the user to execute a tool on your behalf and share the results with you.
    If you want the user to execute a tool on your behalf, strictly only respond with the tool's name and parameters.
    Example response for using tool: websearch('weather in boston today')

    The name of the provided tools and their parameters are given below.
    The output of tool execution will be shared with you so you can decide your next steps.

    ### PROVIDED TOOLS INFORMATION ###
    ##1. Tool to send an email
    Name: send_email
    Parameters: src, dst, subject, content
    example usage: send_email('abc@gmail.com', 'xyz@gmail.com', 'greetings', 'hi, I hope you are well')


    ##2. Tool to perform a websearch and get top 5 webpage links based on input query. This is useful to get information about people, topics etc.
    Name: websearch
    Parameters: query
    example usage: websearch('caching in llms')
    example usage: websearch('lebron james')


    ##3. Tool to request content of a webpage
    Name: get_page
    Parameters: url
    example usage: get_page('openAI.com')
    example usage: get_page('google.com')

    """

    response = generate(model = '4o-mini',
        system = system,
        query = query,
        temperature=0.7,
        lastk=10,
        session_id='DEMO_AGENT_EMAIL',
        rag_usage = False)

    try:
        return response['response']
    except Exception as e:
        print(f"Error occured with parsing output: {response}")
        raise e
    return 


if __name__ == '__main__':


    # Need to substitute X with someone's name
    query = """
    Send an email to X requesting an extension on asg1?
    Use the tools provided if you want
    """

    while True:
        
        response = agent_email(query)

        # print Response
        print(response)

        user_input = input("Enter Y to continue, N to exit, or provide hint to agent: ").strip().upper()
        if user_input == 'N':
            break
        elif user_input == 'Y':

            # extract tool from agent_email's response
            tool = extract_tool(response)

            # if tool found, execute it using `eval`
            # https://docs.python.org/3/library/functions.html#eval
            if tool:
                response = eval(tool)
                print(f"Output from tool: {response}\n\n")        
        else:
            response = user_input

        # Response becomes input for next iteration 
        query = response


