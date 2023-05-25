# Generates a Header from BDS
# @author Frederox
# @category Bedrock

from LibCommon import find_labels_of_class, batch_demangle
from LibFunctionParser import (
    get_arguments,
    get_name,
    do_functions_match,
    get_return_type,
)
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

symbol_map_path = str(askFile("Symbol Map Output", "Choose File"))
print("Symbol Map Output Path: '" + symbol_map_path + "'")

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
        is_return_const = "const" in demangled_symbols[i].split(")")[1]

        functions.append(
            {
                "failed": False,
                "mangled": symbols[i],
                "demangled": demangled_symbols[i],
                "name": get_name(class_name, demangled_symbols[i]),
                "args": get_arguments(demangled_symbols[i]),
                "returns": get_return_type(class_name, demangled_symbols[i]),
                "is_const": is_return_const,
                "is_virtual": "virtual" in demangled_symbols[i],
                "is_static": "static" in demangled_symbols[i],
                "is_public": "public" in demangled_symbols[i],
                "is_private": "private" in demangled_symbols[i],
                "is_protected": "protected" in demangled_symbols[i],
            }
        )

    # Else it is a variable
    else:
        variables.append({"mangled": symbols[i], "demangled": demangled_symbols[i]})

# Match virtual functions to demangled functions
unordered_non_virtual_functions = filter(lambda f: "virtual" not in f["demangled"], functions)
non_virtual_functions = []
virtual_functions = []

monitor.initialize(len(vtable_data))
monitor.setMessage("Matching functions from Vtable to parsed functions")

# Order virtual functions
for entry in vtable_data:
    monitor.incrementProgress(1)

    filtered_func = filter(lambda f: do_functions_match(f, entry), functions)

    if len(filtered_func) != 1:
        print("Failed to find: " + entry["name"])
        print(entry)
        virtual_functions.append({
            "failed": True,
            "name": entry["name"]
        })
        continue

    virtual_functions.append(filtered_func[0])

# Arbitrary order for non virtal functions, organising by visibility
non_virtual_functions += (list(filter(
    lambda f: "public" in f["demangled"],
    unordered_non_virtual_functions
)))

non_virtual_functions += (list(filter(
    lambda f: "private" in f["demangled"],
    unordered_non_virtual_functions
)))

non_virtual_functions += (list(filter(
    lambda f: "protected" in f["demangled"],
    unordered_non_virtual_functions
)))



# Generate Header and Vtable
header_text, symbol_map_text = HeaderLib(
    class_name, virtual_functions, non_virtual_functions, variables
).generate()

with open(header_path, "w") as header_file:
    header_file.write(header_text)

with open(symbol_map_path, "w") as symbol_map_file:
    symbol_map_file.write(symbol_map_text)
