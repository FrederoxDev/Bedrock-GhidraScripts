# With all ", " replaced with ","
type_aliases = {
    "std::__ndk1::basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char> >": "std::string",
    "std::basic_string<char,std::char_traits<char>,std::allocator<char> >": "std::string",
}


def _split_arguments(s):
    arguments = []
    stack = []
    start = 0
    for i, c in enumerate(s):
        if c == "<":
            stack.append("<")
        elif c == ">":
            stack.pop()
        elif c == "," and not stack:
            argument = s[start:i].strip()
            arguments.append(argument)
            start = i + 1
    argument = s[start:].strip()
    arguments.append(argument)
    return arguments


def get_name(class_name, demangled):
    return demangled[
        demangled.find(class_name + "::") + len(class_name) + 2 : demangled.find("(")
    ]


def get_arguments(demangled):
    parameters_str = _split_arguments(
        demangled[demangled.find("(") + 1 : demangled.find(")")]
    )
    new_parameters = []

    for parameter_str in parameters_str:
        is_struct = "struct" in parameter_str
        is_enum = "enum" in parameter_str
        is_class = "class" in parameter_str

        parameter_str = parameter_str.replace("class ", "")
        parameter_str = parameter_str.replace("struct ", "")
        parameter_str = parameter_str.replace("enum ", "")
        parameter_str = parameter_str.replace(" __ptr64", "")

        is_ptr = "*" in parameter_str
        is_reference = "&" in parameter_str
        is_const = "const" in parameter_str

        param_class_name = (
            parameter_str.replace("*", "").replace("&", "").replace("const", "").strip()
        )
        stringified = ""

        if is_const:
            stringified += "const "
        stringified += param_class_name
        if is_ptr:
            stringified += "*"
        if is_reference:
            stringified += "&"

        stringified = stringified.replace(", ", ",")
        param_class_name = param_class_name.replace(", ", ",")

        for type_name, alias in type_aliases.items():
            stringified = stringified.replace(type_name, alias)
            param_class_name = param_class_name.replace(type_name, alias)

        if stringified != "":
            new_parameters.append(
                {
                    "type": stringified,
                    "base_type": param_class_name,
                    "is_struct": is_struct,
                    "is_enum": is_enum,
                    "is_class": is_class,
                }
            )

    if len(new_parameters) == 1 and new_parameters[0]["type"] == "void":
        new_parameters = []

    return new_parameters


def get_return_type(demangled):
    demangled = (
        demangled.replace("public: ", "")
        .replace("private: ", "")
        .replace("static ", "")
        .replace("virtual ", "")
        .replace("protected: ", "")
    )
    demangled = demangled[0 : demangled.find("Item::")]

    is_return_const = "const" in demangled
    is_return_ptr = "*" in demangled
    is_return_ref = "&" in demangled
    is_return_enum = "enum" in demangled
    is_return_struct = "struct" in demangled
    is_return_class = "class" in demangled

    demangled = (
        demangled.replace("__cdecl", "")
        .replace("class", "")
        .replace("__ptr64", "")
        .replace("enum", "")
        .replace("struct", "")
        .replace("const", "")
    )
    demangled = demangled.replace("*", "").replace("&", "").strip()

    base_type = demangled

    if is_return_const:
        demangled = "const " + demangled
    if is_return_ptr:
        demangled += "*"
    if is_return_ref:
        demangled += "&"

    demangled = demangled.replace(", ", ",")
    base_type = base_type.replace(", ", ",")

    for type_name, alias in type_aliases.items():
        demangled = demangled.replace(type_name, alias)
        base_type = base_type.replace(type_name, alias)

    return {
        "type": demangled,
        "base_type": base_type,
        "is_enum": is_return_enum,
        "is_struct": is_return_struct,
        "is_class": is_return_class,
    }


def do_functions_match(first, second):
    """
    Checks if two parsed functions are equivallent
    """

    if first["name"] != second["name"]:
        return False
    
    if len(first["args"]) != len(second["args"]):
        return False
    
    for i in range(len(first["args"])):
        if first["args"][i]["type"] != second["args"][i]["type"]:
            return False
    
    return True