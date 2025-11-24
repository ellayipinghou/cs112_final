from llmproxy import (
    retrieve,
    generate,
    text_upload

)

from string import Template
from time import sleep

# function to create a context string from retrieve's return val
def rag_context_string_simple(rag_context):

    context_string = ""

    i=1
    for collection in rag_context:
    
        if not context_string:
            context_string = """The following is additional context that may be helpful in answering the user's query."""

        context_string += """
        #{} {}
        """.format(i, collection['doc_summary'])
        j=1
        for chunk in collection['chunks']:
            context_string+= """
            #{}.{} {}
            """.format(i,j, chunk)
            j+=1
        i+=1
    return context_string

if __name__ == '__main__':

    # adding several documents to session_id=RAG
    # DOC1
    response = text_upload(
        text = """
        Once upon a time, in the faraway land of Citrusville, there was a man named Orange Jim.
        Now, Orange Jim wasn't your average Joe—oh no, he was really average in every sense,
        except for one glaring, fruit-inspired trait: he was the color orange.
        Not just a little orange but a deep, radiant orange, like a tangerine on a sunbeam,
        or the kind of sunset that makes you question the existence of sunsets.
        """,
        session_id='RAG',
        strategy='fixed')

    # DOC2
    response = text_upload(
        text = """
        Orange Jim is also an industrialist
        """,
        session_id='RAG',
        strategy='fixed')

    # sleep so documents are added to session_id=RAG
    sleep(20)

    # Query used to retrieve relevant context
    query = 'Tell me about Orange Jim?'

    # assuming some document(s) has previously been uploaded to session_id=RAG
    rag_context = retrieve(
        query =query,
        session_id='RAG',
        rag_threshold = 0.2,
        rag_k = 3)

    # combining query with rag_context
    query_with_rag_context = Template("$query\n$rag_context").substitute(
                            query=query,
                            rag_context=rag_context_string_simple(rag_context))

    # Pass to LLM using a different session (session_id=GenericSession)
    # You can also set rag_usage=True to use RAG context from GenericSession
    response = generate(model = '4o-mini',
        system = 'Answer my question',
        query = query_with_rag_context,
        temperature=0.0,
        lastk=0,
        session_id='GenericSession',
        rag_usage = False
        )

    print(response)