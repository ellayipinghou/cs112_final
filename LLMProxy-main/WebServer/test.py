import requests

response_main = requests.post("https://replace_with_your_web_server_link")
print('Web Application Response:\n', response_main.text, '\n\n')


data = {"text":"tell me about tufts"}
response_llmproxy = requests.post("https://replace_with_your_web_server_link/query", json=data)
print('LLMProxy Response:\n', response_llmproxy.text)
