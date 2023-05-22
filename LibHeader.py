class HeaderLib:
    def __init__(self, virtual_functions):
        self.class_set = set()
        self.struct_set = set()
        self.enum_set = set()
        self.virtual_functions = virtual_functions
        self.last_modifier = ""
        self.text = ""

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
        # Generate incomplete types from return type
        if function["returns"]["is_struct"]:
            self.struct_set.add(function["returns"]["base_type"])

        elif function["returns"]["is_enum"]:
            self.enum_set.add(function["returns"]["base_type"])

        elif function["returns"]["is_class"]:
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
        signature += self.parse_args(function["args"]) + ");\n"
        self.text += signature

    def to_text(self):
        header_text = "// File automatically generated from GenerateHeader.py\n"
        header_text += "// https://github.com/FrederoxDev/Bedrock-GhidraScripts\n\n"

        for function in self.virtual_functions:
            self.parse_function(function)

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
                header_text += "//"
            header_text += "enum " + enum_name + ";\n"

        # Main class file
        header_text += "\nclass Item {\n"
        header_text += self.text
        header_text += "};"

        return header_text
