class InitRequired(Exception):
    pass

def run():
    raise InitRequired("axiom-test is not initialized. Please run: python3 -m axiom_test init")
