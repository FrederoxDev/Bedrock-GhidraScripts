# Generates a Header from BDS
# @author Frederox
# @category Bedrock

from LibCommon import find_labels_of_class, batch_demangle
from LibFunctionParser import get_arguments, get_name, do_functions_match, get_return_type
from LibHeader import HeaderLib
import json

class_name = "Item"

# Import dumped virtual table from the Android Client
vtable_data_path = str(askFile("Vtable Data", "Choose File"))
print("Vtable Path: '" + vtable_data_path + "'")
vtable_data = None

with open(vtable_data_path, "r") as vtable_file:
    vtable_data = json.loads(vtable_file.read())

header_path = str(askFile("Header Output", "Choose File"))
print("Header Output Path: '" + header_path + "'")

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
            "args": get_arguments(demangled_symbols[i]),
            "returns": get_return_type(demangled_symbols[i]),
            "is_virtual": "virtual" in demangled_symbols[i],
            "is_static": "static" in demangled_symbols[i],
            "is_public": "public" in demangled_symbols[i],
            "is_private": "private" in demangled_symbols[i],
            "is_protected": "protected" in demangled_symbols[i],
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
with open(header_path, "w") as header_file:
    header_file.write(
        HeaderLib(virtual_functions).to_text()
    )