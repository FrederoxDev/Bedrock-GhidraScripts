#Extracts Android
#@author Frederox
#@category Bedrock

import json
from LibFunctionParser import get_arguments, get_class_name
import os

desktop_path = os.path.expandvars("%userprofile%\\Desktop\\HeaderOut")

if not os.path.exists(desktop_path):
    os.makedirs(desktop_path)

program = getCurrentProgram()
function_manager = program.getFunctionManager()
listing = program.getListing()

address_size = 8;

start_address = askAddress(None, "Enter start address")
end_address = askAddress(None, "Enter end address").add(address_size)
offset = end_address.subtract(start_address)
buffer = getBytes(start_address, offset)

class_name = askString(None, "Enter class name")
inherits = askString(None, "Enter all inherited classes seperated by a comma").split(",")

print(class_name)
print(inherits)

functions = []

# Iterate each function addr in the vtable
for i in range(0, offset, address_size):
    try:
        func_data = listing.getDataAt(start_address.add(i))
        func_address = func_data.getValue()
        func = function_manager.getFunctionContaining(func_address)
        args = get_arguments(func.getComment())
        
        # If the class inherits a function from another class dont include it again
        # If it has not been replaced by the current class
        if get_class_name(func.getComment()) != class_name:
            continue

        functions.append({
            "failed": False,
            "name": func.getName(),
            "args": args
        })

    except AttributeError as e:
        print("Crashed reading address: " + str(start_address.add(i)))
        print(e)

        functions.append({
            "failed": True
        })
        continue

file_data = {
    "class_name": class_name,
    "inherits": inherits,
    "functions": functions
}

with open(desktop_path + "\\dumpedVtable.json", "w") as file:
    file.write(json.dumps(file_data, indent=4))