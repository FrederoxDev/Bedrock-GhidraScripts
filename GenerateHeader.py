#Generates the header file from Extracted vtable data
#@author Frederox
#@category Bedrock

from BedrockCommon import parse_function, create_function_signature, get_arguments, do_args_match
from ghidra.program.model.symbol import SymbolType
import json

fm = currentProgram.getFunctionManager()
symbolTable = currentProgram.getSymbolTable()

class_name = "Item"
data_file_path = str(askFile("Vtable Data", "Choose File"))
vtable_data = None

# Get all functions accosiated with the class
class_functions = filter(
    lambda f: f.getParentNamespace() is not None and f.getParentNamespace().getName() == class_name, 
    fm.getFunctions(True)
)

# Reading dumped data from the android vtable
with open(data_file_path, "r") as data_file:
    vtable_data = json.loads(data_file.read())

virtual_functions = []
virtual_function_set = set()

# Link the virtual function from the android vtable to one in the server
for entry in vtable_data:
    filtered_funcs = filter(
        lambda f: f.getName() == entry["name"],
        class_functions
    )

    filtered_funcs = filter(
        lambda f: do_args_match(entry, get_arguments(f)),
        filtered_funcs
    )

    if (len(filtered_funcs) == 0):
        virtual_functions.append({
            "replace_with_filler": True,
            "name": entry["name"]
        })
        virtual_function_set.add(entry["name"])

    elif (len(filtered_funcs) > 1):
        print("Found multiple functions for '" + entry["name"] + "'")

    else:
        virtual_functions.append(filtered_funcs[0])
        virtual_function_set.add(entry["name"])

# Non virtual functions
non_virtual_functions = filter(
    lambda f: not (f.getName() in virtual_function_set),
    class_functions
)

# Sets used to create incomplete types at the top of the file
class_set = set()
struct_set = set()
enum_set = set()

file_text = "// File automatically generated from GenerateHeader.py\n"
file_text += "// Script written by FrederoxDev\n\n"
last_modifier = ""

class_text = "class " + class_name + " {\n"
filler_index = 0

signature_set = set()

symbol_map = {
    "vtable": [
        {
            "name": class_name,
            "address": "",
            "functions": []
        }
    ]
}

# Create class Text
for function in virtual_functions:
    # For functions which are in the android vtable, but are not in the bds class
    # Also giving enough information via comment so that if needed, they can be written manually 
    if type(function) is dict and function["replace_with_filler"]:
        class_text += "  virtual void filler" + str(filler_index) + "() {}; // " + function["name"] + "\n"
        filler_index += 1
        symbol_map["vtable"][0]["functions"].append("")
        continue

    func_data = parse_function(function)
    signature = create_function_signature(function, func_data)

    # Removes duplicate dtors
    if signature in signature_set:
        print("Skipped duplicate function: '" + signature + "'")
        continue
    
    else:
        signature_set.add(signature)

    # Add symbol for symbol mapping
    symbols = list(symbolTable.getSymbols(function.getEntryPoint()))

    symbols = filter(
        lambda s: s.getSymbolType() == SymbolType.LABEL,
        symbols
    )

    if len(symbols) != 1:
        print(signature)
        for symbol in symbols:
            print(symbol)
        print(" ")

    symbol_map["vtable"][0]["functions"].append(symbols[len(symbols) - 1].getName())
        
    # Add argument types to set
    for arg in func_data["args"]:
        if arg["is_struct"]: struct_set.add(arg["base_type"])
        elif arg["is_enum"]: enum_set.add(arg["base_type"]) 
        elif arg["is_class"]: class_set.add(arg["base_type"]) 

    # Add return type to set
    returns = func_data["returns"]
    if returns["is_enum"]: enum_set.add(returns["base_type"])
    elif returns["is_struct"]: struct_set.add(returns["base_type"])
    elif returns["is_class"]: class_set.add(returns["base_type"])

    if func_data["is_public"] and last_modifier != "public":
        class_text += "public:\n"
        last_modifier = "public"

    elif func_data["is_private"] and last_modifier != "private":
        class_text += "private:\n"
        last_modifier = "private"

    elif func_data["is_protected"] and last_modifier != "protected":
        class_text += "protected:\n"
        last_modifier = "protected"

    class_text += "  " + signature + "\n"

# Place non virtual functions at the end of the class
for function in non_virtual_functions:
    func_data = parse_function(function)
    signature = create_function_signature(function, func_data)

    symbols = list(symbolTable.getSymbols(function.getEntryPoint()))

    symbols = filter(
        lambda s: s.getSymbolType() == SymbolType.LABEL,
        symbols
    )

    if len(symbols) != 1:
        print(signature)
        for symbol in symbols:
            print(symbol)
        print(" ")

    symbol_map["vtable"][0]["functions"].append(symbols[len(symbols) - 1].getName())

    # Add argument types to set
    for arg in func_data["args"]:
        if arg["is_struct"]: struct_set.add(arg["base_type"])
        elif arg["is_enum"]: enum_set.add(arg["base_type"]) 
        elif arg["is_class"]: class_set.add(arg["base_type"]) 

    # Add return type to set
    returns = func_data["returns"]
    if returns["is_enum"]: enum_set.add(returns["base_type"])
    elif returns["is_struct"]: struct_set.add(returns["base_type"])
    elif returns["is_class"]: class_set.add(returns["base_type"])

    if func_data["is_public"] and last_modifier != "public":
        class_text += "public:\n"
        last_modifier = "public"

    elif func_data["is_private"] and last_modifier != "private":
        class_text += "private:\n"
        last_modifier = "private"

    elif func_data["is_protected"] and last_modifier != "protected":
        class_text += "protected:\n"
        last_modifier = "protected"

    class_text += "  " + signature + "\n"

class_text += "};"

file_text += "#include <string>\n"

# Don't include incomplete types inside namespaces
for item in class_set:
    if "::" in item:
        class_set.remove(item)

for item in enum_set:
    if "::" in item:
        enum_set.remove(item)

for item in struct_set:
    if "::" in item:
        struct_set.remove(item)

# Add Incomplete types
for class_name_i in class_set:
    file_text += "class " + class_name_i + ";\n"

for struct_name in struct_set:
    file_text += "struct " + struct_name + ";\n"

for enum_name in enum_set:
    file_text += "enum " + enum_name + ";\n"

file_text += "\n"
file_text += class_text

header_file_path = str(askFile("Header File", "Choose File"))
symbol_map_path = str(askFile("Symbol Map", "Choose File"))

with open(header_file_path, "w") as header_file:
    header_file.write(file_text)

with open(symbol_map_path, "w") as symbol_map_file:
    symbol_map_file.write(json.dumps(symbol_map, indent=4))