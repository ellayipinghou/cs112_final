from llmproxy import retrieve

if __name__ == '__main__':
    response = retrieve(
        query = 'Tell me about Orange Jim?',
        session_id='GenericSession',
        rag_threshold = 0.5,
        rag_k = 1)

    print(response)