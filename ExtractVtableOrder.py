#Extracts Android
#@author Frederox
#@category Bedrock

import json
from LibFunctionParser import get_arguments

program = getCurrentProgram()
function_manager = program.getFunctionManager()

start_address = askAddress(None, "Enter start address")
end_address = askAddress(None, "Enter end address").add(4)
offset = end_address.subtract(start_address)

buffer = getBytes(start_address, offset)
functions = []

# Iterate each function addr in the vtable
for i in range(0, offset, 4):
    func_address = program.getListing().getDataAt(start_address.add(i)).getValue()
    func = function_manager.getFunctionContaining(func_address)
    args = get_arguments(func.getComment())

    functions.append({
        "name": func.getName(),
        "args": args
    })

file_path = str(askFile("Vtable Data", "Choose File: "))

with open(file_path, "w") as file:
    file.write(json.dumps(functions, indent=4))