# TODO: Write this
# @author Frederox
# @category Bedrock

from BedrockLib import find_labels_of_class, batch_demangle
from FunctionParserLib import get_arguments, get_name, do_functions_match
import json

class_name = "Item"

# Import dumped virtual table from the Android Client
vtable_data_path = str(askFile("Vtable Data", "Choose File"))
vtable_data = None

print("Vtable Path: '" + vtable_data_path + "'")

with open(vtable_data_path, "r") as vtable_file:
    vtable_data = json.loads(vtable_file.read())

# Finds all symbols which belong to the class and demangle them into functions
symbols = find_labels_of_class(currentProgram, monitor, class_name)
demangled_symbols = batch_demangle(monitor, symbols)

# Sort out the symbols into functions and variables
# Also parse name and arguments for functions
functions = []
variables = []

monitor.initialize(len(symbols))
monitor.setMessage("Parsing demangled functions")

for i in range(len(symbols)):
    monitor.incrementProgress(1)

    # If it contains ( it is a function
    if "(" in demangled_symbols[i]:
        functions.append({
            "mangled": symbols[i],
            "demangled": demangled_symbols[i],
            "name": get_name(class_name, demangled_symbols[i]),
            "args": get_arguments(demangled_symbols[i])
        })

    # Else it is a variable
    else:
        variables.append({
            "mangled": symbols[i],
            "demangled": demangled_symbols[i]
        })

# Match virtual functions to demangled functions
virtual_functions = []

monitor.initialize(len(vtable_data))
monitor.setMessage("Matching functions from Vtable to parsed functions")

for entry in vtable_data:
    monitor.incrementProgress(1)

    filtered_func = filter(
        lambda f: do_functions_match(f, entry),
        functions
    )

    if len(filtered_func) != 1:
        print("Failed to find: " + entry["name"])
        exit(1)

    virtual_functions.append(filtered_func[0])

# Generate header file
for virtual_func in virtual_functions:
    print("Found: " + virtual_func["name"])