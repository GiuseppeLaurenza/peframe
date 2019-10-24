import logging
import os

import pandas as pd
import r2pipe

DEBUG = os.getenv("DEBUG","0")
# DEBUG = 1
LOGGER = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s')
if DEBUG == "1":
    LOGGER.setLevel(logging.DEBUG)
else:
    LOGGER.setLevel(logging.INFO)

# def decode_strings(type, string):
def decode_strings(element):
    type = element.get("type", None)
    string = element.get("string", "")
    try:
        if type== "utf8":
            string = string.decode("utf-8")
        elif type=="utf16":
            string = string.decode("utf-16")
        elif type=="ascii":
            string = string.decode("ascii")
        else:
            string = string.decode("ascii", "ignore")
    except:
        try:
            string = string.decode("ascii", "ignore")
        except:
            try:
                string = string.decode("utf-8", "ignore")
            except:
                try:
                    string = string.decode("utf-16", "ignore")
                except AttributeError as e:
                    string = string
    element["string"] = string
    return element

# def r2_analysis(sample_file_path):
#     LOGGER.debug("RADARE2: open file")
#     r2 = r2pipe.open(sample_file_path)
#     # LOGGER.debug("RADARE2: before aei")
#     # r2.cmd("aei")
#     # LOGGER.debug("RADARE2: before aeim")
#     # r2.cmd("aeim")
#     # LOGGER.debug("RADARE2: before aaaa")
#     # r2.cmd("aaaa")
#     # LOGGER.debug("RADARE2: before aaaap")
#     # r2.cmd("aaaap")
#     # LOGGER.debug("RADARE2: before afll")
#     # section_info_string = r2.cmd("S")
#     # executable_section_index_list = [i for i, x in enumerate(section_info_string.split("\n")) if ("*" in x)]
#     # section_command_list = [x for x in r2.cmd("S*").split("\n") if x.startswith("S")]
#     # executable_command_list = [section_command_list[i] for i in executable_section_index_list]
#     # for s in executable_command_list:
#     #     if not s.endswith("x"):
#     #         s = s.replace(s[len(s) - 1], 'x')
#     #         r2.cmd(s)
#     r2.cmd("aaa")
#     r2.cmd("aap")
#     function_string = r2.cmd("afll").split()
#     # columns_list = ["address", "size",  "nbbs", "edges",    "cc", "cost",   "min bound", "range", "max bound",   "calls", "locals", "args", "xref", "frame", "name"]
#     # element_list = [function_string[k:(k + len(columns_list))] for k in range(32, len(function_string), len(columns_list))]
#     # functions_df=pd.DataFrame(element_list, columns=columns_list)
#     functions_df = pd.DataFrame(r2.cmdj("aflj"))
#     LOGGER.debug("RADARE2: before izj")
#     string_list = r2.cmdj("izzj")
#     string_df = pd.DataFrame(string_list["strings"]).fillna("")
#     string_df = string_df.apply(decode_strings, axis=1)
#
#     result = dict()
#     LOGGER.debug("RADARE2: before iej")
#     result["entry_points"] = r2.cmdj("iej")
#     result["function_size_opcodes"] = functions_df.to_dict(orient="records")
#     result["decoded_strings"] = string_df.to_dict(orient="records")
#     LOGGER.debug("RADARE2: before irj")
#     try:
#         result["relocations"] = r2.cmdj("irj")
#         result["stats"] = {"functions": len(result["function_size_opcodes"]),
#                            "relocations": len(result["relocations"]),
#                            "strings (see raw report for details)": len(result["decoded_strings"])}
#     except Exception as e:
#         LOGGER.info("Relocations error " + str(e))
#         result["stats"] = {"functions": len(result["function_size_opcodes"]),
#                            # "relocations": len(result["relocations"]),
#                            "strings (see raw report for details)": len(result["decoded_strings"])}
#         pass
#     r2.quit()
#     return result


def r2_analysis(sample_file_path):
    r2 = r2pipe.open(sample_file_path,["-2"])
    base = int(r2.cmd("?v $B"),16)
    # LOGGER.info(sample_file_path + " - aaa")
    r2.cmd("aaa")
    # LOGGER.info(sample_file_path + " - aap")
    r2.cmd("aap")
    # LOGGER.info(sample_file_path + " - aab")
    r2.cmd("aab")
    functions_df = pd.DataFrame(r2.cmdj("aflj"))
    string_list = r2.cmdj("izzj")
    string_df = pd.DataFrame(string_list).fillna("")
    string_df = string_df.apply(decode_strings, axis=1)

    result = dict()
    # LOGGER.debug("RADARE2: before iej")
    result["entry_points"] = r2.cmdj("iej")
    result["function_size_opcodes"] = functions_df.to_dict(orient="records")
    result["decoded_strings"] = string_df.to_dict(orient="records")
    # LOGGER.debug("RADARE2: before irj")
    try:
        result["relocations"] = r2.cmdj("irj")
        result["stats"] = {"functions": len(result["function_size_opcodes"]),
                           "relocations": len(result["relocations"]),
                           "strings (see raw report for details)": len(result["decoded_strings"])}
    except Exception as e:
        LOGGER.info("Relocations error " + str(e))
        result["stats"] = {"functions": len(result["function_size_opcodes"]),
                           # "relocations": len(result["relocations"]),
                           "strings (see raw report for details)": len(result["decoded_strings"])}
        pass
    r2.quit()
    return result

