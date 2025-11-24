from llmproxy import model_info

if __name__ == '__main__':
    response = model_info()

    print(response['result'])