#Extracts Android
#@author Frederox
#@category Bedrock

import json
from LibFunctionParser import get_arguments

program = getCurrentProgram()
function_manager = program.getFunctionManager()
listing = program.getListing()

address_size = askInt(None, "Enter address size in vtable");

start_address = askAddress(None, "Enter start address")
end_address = askAddress(None, "Enter end address").add(address_size)
offset = end_address.subtract(start_address)

print("Offset: " + str(offset))

buffer = getBytes(start_address, offset)
functions = []

# Iterate each function addr in the vtable
for i in range(0, offset, address_size):
    try:
        func_data = listing.getDataAt(start_address.add(i))
        func_address = func_data.getValue()
        func = function_manager.getFunctionContaining(func_address)
        args = get_arguments(func.getComment())

        functions.append({
            "name": func.getName(),
            "args": args
        })

    except AttributeError as e:
        print("Crashed reading address: " + str(start_address.add(i)))
        print(e)
        continue

file_path = str(askFile("Vtable Data", "Choose File: "))

with open(file_path, "w") as file:
    file.write(json.dumps(functions, indent=4))