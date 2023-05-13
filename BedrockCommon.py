# Library functions for scripts

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

# With all ", " replaced with ","
type_aliases = {
    "std::__ndk1::basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char> >": "std::string",
    "std::basic_string<char,std::char_traits<char>,std::allocator<char> >": "std::string"
}

def get_arguments(function):
    comment = function.getComment()
    parameters_str = _split_arguments(comment[comment.find('(') + 1 : comment.find(')')])
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

        param_class_name = parameter_str.replace("*", "").replace("&", "").replace("const", "").strip()
        stringified = ""

        if is_const: stringified += "const "
        stringified += param_class_name
        if is_ptr: stringified += "*"
        if is_reference: stringified += "&"

        stringified = stringified.replace(", ", ",")
        param_class_name = param_class_name.replace(", ", ",")

        for type_name, alias in type_aliases.items():
            stringified = stringified.replace(type_name, alias)
            param_class_name = param_class_name.replace(type_name, alias)

        if stringified != "":
            new_parameters.append({
                "type": stringified,
                "base_type": param_class_name,
                "is_struct": is_struct,
                "is_enum": is_enum,
                "is_class": is_class
            })

    if len(new_parameters) == 1 and new_parameters[0]["type"] == "void":
        new_parameters = []

    return new_parameters

def parse_function(f):
    comment = f.getComment()

    is_public = "public" in comment
    is_private = "private" in comment
    is_static = "static" in comment
    is_virtual = "virtual" in comment
    is_protected = "protected" in comment

    return {
        "name": f.getName(),
        "args": get_arguments(f),
        "returns": parse_function_return(f),
        "is_public": is_public,
        "is_private": is_private,
        "is_static": is_static,
        "is_virtual": is_virtual,
        "is_protected": is_protected
    }
    
def parse_function_return(f):
    comment = f.getComment()
    comment_ret = comment.replace("public: ", "").replace("private: ", "").replace("static ", "").replace("virtual ", "").replace("protected: ", "")
    comment_ret = comment_ret[0 : comment_ret.find('Item::')]

    is_return_const = "const" in comment_ret
    is_return_ptr = "*" in comment_ret
    is_return_ref = "&" in comment_ret
    is_return_enum = "enum" in comment_ret
    is_return_struct = "struct" in comment_ret
    is_return_class = "class" in comment_ret

    comment_ret = comment_ret.replace("__cdecl", "").replace("class", "").replace("__ptr64", "").replace("enum", "").replace("struct", "").replace("const", "")
    comment_ret = comment_ret.replace("*", "").replace("&", "").strip()

    base_type = comment_ret

    if is_return_const: comment_ret = "const " + comment_ret
    if is_return_ptr: comment_ret += "*"
    if is_return_ref: comment_ret += "&"

    comment_ret = comment_ret.replace(", ", ",")
    base_type = base_type.replace(", ", ",")

    for type_name, alias in type_aliases.items():
        comment_ret = comment_ret.replace(type_name, alias)
        base_type = base_type.replace(type_name, alias)

    return {
        "type": comment_ret,
        "base_type": base_type,
        "is_enum": is_return_enum,
        "is_struct": is_return_struct,
        "is_class": is_return_class
    }

def create_function_signature(function, parsed_data):
    signature = ""
    if parsed_data["is_static"]: signature += "static "
    if parsed_data["is_virtual"]: signature += "virtual "

    if parsed_data["returns"]["type"] != "":
        signature += parsed_data["returns"]["type"] + " "

    signature += function.getName() 

    args = []
    for arg in parsed_data["args"]:
        args.append(arg["type"])

    stringified_args = str(args).replace("[", "").replace("]", "").replace("u'", "").replace("'", "")
    signature += "(" + stringified_args + ");"

    return signature

def parsed_args_to_simple(args):
    simplified = []
    for arg in args:
        simplified.append(arg["type"])

    return simplified

def do_args_match(vtable_args, other):
    if len(vtable_args["args"]) != len(other): return False

    other = parsed_args_to_simple(other)

    for index, arg in enumerate(vtable_args["args"]):
        if arg["type"] != other[index]: return False

    return True