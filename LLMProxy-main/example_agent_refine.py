import sys
import os

from llmproxy import generate

def agent_QA(query):
    system = """
    You are an AI agent designed critque code written by a junior programmer for animating physics concepts.
    The task given to the programmer is to write code for simulating a ball bouncing inside a hexagon.

    You have two options:
    ### Option 1 ###
    If you see any issues, respond with pointing any bugs,
    suggestions for simplifying, improving, and optimizing the code.
    Most importantly, focus on adherence to physics principles like gravity, friction etc.
    Do not write actual code. 
    
    ### Option 2 ###
    2. If you don't see any issues with the code, respond with the keyword `$$EXIT$$` and nothing else.
    """

    response = generate(model = '4o-mini',
        system = system,
        query = """Code:\n\n{}""".format(query),
        temperature=0.3,
        lastk=10,
        session_id='DEMO_AGENT_QA',
        rag_usage = False)

    try:
        return response['response']
    except Exception as e:
        print(f"Error occured with parsing output: {response}")
        raise e
    return 

def agent_coder(query):

    system = """
    You are an AI agent designed to write code.
    """

    response = generate(model = '4o-mini',
        system = system,
        query = query,
        temperature=0.3,
        lastk=10,
        session_id='DEMO_AGENT_CODER',
        rag_usage = False)

    try:
        return response['response']
    except Exception as e:
        print(f"Error occured with parsing output: {response}")
        raise e

    return

if __name__ == '__main__':
    query = """
    Write an animation as an HTML code showing a ball bouncing inside a spinning hexagon.
    The bouncing ball should be affected by gravity, friction, collisions with the hexagon boundaries.
    Pay special attention to realistic physics.
    Your response should only contain the the HTML code and nothing else.
    I should be able to run this animation on my browser.
    """

    agents = [agent_coder, agent_QA]

    max_iterations = 1

    i=0;
    while i < max_iterations:

        # flip between agent coder and QA
        active_agent = agents[i%2]


        query = active_agent(query)

        if query == "$$EXIT$$":
            break

        i+=1



