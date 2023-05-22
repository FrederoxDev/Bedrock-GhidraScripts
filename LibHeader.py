import json

class HeaderLib:
    def __init__(self, class_name, virtual_functions, non_virtual_functions, variables):
        self.class_set = set()
        self.struct_set = set()
        self.enum_set = set()
        self.demangled_set = set()
        self.virtual_functions = virtual_functions
        self.non_virtual_functions = non_virtual_functions
        self.variables = variables
        self.class_name = class_name
        self.last_modifier = ""
        self.text = ""

        self.symbol_map = {
            "vtable": [
                {
                    "name": self.class_name,
                    "address": "",
                    "functions": []
                }
            ]
        }

    def parse_args(self, args):
        """
        Stringifies an array of function arguments
        """
        base_types = []
        for arg in args:
            base_types.append(arg["type"])

        return (
            str(base_types)
            .replace("[", "")
            .replace("]", "")
            .replace("u'", "")
            .replace("'", "")
        )

    def parse_function(self, function):
        """
        Parses function data
        """
        if function["demangled"] in self.demangled_set:
            print("Skipping duplicate: " + function["name"])
            return
        
        self.demangled_set.add(function["demangled"])

        self.symbol_map["vtable"][0]["functions"].append(function["mangled"])
        
        # Generate incomplete types from return type
        if function["returns"]["is_struct"]:
            self.struct_set.add(function["returns"]["base_type"])

        if function["returns"]["is_enum"]:
            self.enum_set.add(function["returns"]["base_type"])

        if function["returns"]["is_class"]:
            self.class_set.add(function["returns"]["base_type"])

        # Function modifiers
        signature = ""
        if function["is_public"] and self.last_modifier != "public":
            signature += "public:\n"
            self.last_modifier = "public"

        elif function["is_private"] and self.last_modifier != "private":
            signature += "private:\n"
            self.last_modifier = "private"

        elif function["is_protected"] and self.last_modifier != "protected":
            signature += "protected:\n"
            self.last_modifier = "protected"

        signature += "\t"

        # Function modifiers
        if function["is_static"]:
            signature += "static "

        elif function["is_virtual"]:
            signature += "virtual "

        # Add return type to signature
        ret_type = function["returns"]["type"]

        if ret_type != "":
            signature += ret_type + " "

        # Add function name to signature
        signature += function["name"] + "("

        # Generate incomplete types from function arguments
        for arg in function["args"]:
            if arg["is_struct"]:
                self.struct_set.add(arg["base_type"])

            elif arg["is_enum"]:
                self.enum_set.add(arg["base_type"])

            elif arg["is_class"]:
                self.class_set.add(arg["base_type"])

        # Add function arguments
        signature += self.parse_args(function["args"]) + ")"
        if function["is_const"]:
            signature += " const"
        signature += ";\n"
        self.text += signature

    def generate(self):
        header_text = "// File automatically generated from GenerateHeader.py\n"
        header_text += "// https://github.com/FrederoxDev/Bedrock-GhidraScripts\n\n"

        for function in self.virtual_functions:
            self.parse_function(function)

        self.text += "\n// Begin Non-Virtual Functions\n"
        for function in self.non_virtual_functions:
            self.parse_function(function)

        self.text += "\n// Begin Variables\n"
        for variable in self.variables:
            self.text += "// " + variable["demangled"] + ";\n"

        # Generate incomplete types
        header_text += "#pragma once\n"
        header_text += "#include <string>\n"
        for class_name_i in self.class_set:
            if "::" in class_name_i:
                header_text += "// "
            header_text += "class " + class_name_i + ";\n"

        for struct_name in self.struct_set:
            if "::" in struct_name:
                header_text += "// "
            header_text += "struct " + struct_name + ";\n"

        for enum_name in self.enum_set:
            if "::" in enum_name:
                header_text += "// "
            header_text += "enum " + enum_name + ";\n"

        header_text += "\n"

        # Main class file
        header_text += "\nclass Item {\n"
        header_text += self.text
        header_text += "};"

        header_vtable = json.dumps(self.symbol_map, indent=4)

        return header_text, header_vtable
