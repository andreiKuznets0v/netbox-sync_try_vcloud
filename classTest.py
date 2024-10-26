class basic():
    type = "basic"
    name = None
    def __init__(self) -> None:
        pass

    def get_type(self):
        print(f"class type is {self.type}")

class parent1(basic):
    type = "parent1"
    def __init__(self, name=None):
        if name is None:
            raise ValueError(f"Invalid value for attribute 'name': '{name}'.")
        self.name = name
        print("parent1 init")
    def get_name(self):
        print(f"class name is {self.name}")



class parent2(parent1):
    #type = "parent2"
    def __init__(self, name=None):
        if name is None:
            raise ValueError(f"Invalid value for attribute 'name': '{name}'.")
        #self.name = name
    def get_type(self):
        print(f"class type from parent2 is {self.type}")


parent2obj = parent2("NewParen2Child")
parent2obj.get_name()
parent2obj.get_type()
#value = "test1:test2:test3"
#print(value.split(':'))