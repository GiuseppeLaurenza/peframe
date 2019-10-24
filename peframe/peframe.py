#!/usr/bin/env python
# -*- coding: utf-8 -*-

# by Gianni 'guelfoweb' Amato

import os
import re
import sys
import json
import magic
import pefile
import hashlib
import pandas as pd
from datetime import datetime

portable = False
for path in sys.path:
    if os.sep + 'peframe' + os.sep + 'peframe' in path:
        portable = True
if portable:
    from modules import directories
    from modules import features
    from modules import apialert
    from modules import yara_check
    from modules import meta
    from modules import virustotal
    from modules import sections
    from modules import fileurl
    from modules import macro
    from modules import headers
    from modules import nucleus
else:
    from peframe.modules import directories
    from peframe.modules import features
    from peframe.modules import apialert
    from peframe.modules import yara_check
    from peframe.modules import meta
    from peframe.modules import virustotal
    from peframe.modules import sections
    from peframe.modules import fileurl
    from peframe.modules import macro
    from peframe.modules import headers
    from peframe.modules import nucleus


def version():
    return "6.0.3"


def get_datetime_now():
    return datetime.now()


def isfile(filename):
    if os.path.isfile(filename):
        return True
    return False


def ispe(filename):
    if re.match(r'^PE[0-9]{2}|^MS-DOS', filetype(filename)):
        return True
    return False


def filetype(filename):
    return magic.from_file(filename)


def filesize(filename):
    return os.path.getsize(filename)


def get_imphash(filename):
    pe = pefile.PE(filename)
    return pe.get_imphash()


def gethash(filename):
    hashinfo = {}

    fh = open(filename, 'rb')
    m = hashlib.md5()
    s = hashlib.sha1()
    s256 = hashlib.sha256()

    while True:
        data = fh.read(8192)
        if not data:
            break

        m.update(data)
        s.update(data)
        s256.update(data)

    hashinfo.update({"md5": m.hexdigest(), "sha1": s.hexdigest(), "sha256": s256.hexdigest()})

    return hashinfo


def path_to_file(filename, folder):
    _ROOT = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(_ROOT, folder, filename)


def load_config(config_file):
    with open(config_file) as conf:
        data = json.load(conf)
    return data


def files_to_edit():
    path = {
        "api_config": path_to_file('config-peframe.json', 'config'),
        "string_match": path_to_file('stringsmatch.json', 'signatures'),
        "yara_plugins": path_to_file('yara_plugins', 'signatures')
    }
    return path


def analyze(filename):
    if not isfile(filename):
        exit("File not found")

    dt_start = get_datetime_now()

    fileinfo = {
        "version": version(),
        "filename": filename,
        "filetype": filetype(filename),
        "filesize": filesize(filename),
        # "virustotal": virustotal.get_result(
        # 	load_config(
        # 		path_to_file('config-peframe.json', 'config'))['virustotal'],
        # 	gethash(filename)['md5']),
    }

    hashes = gethash(filename)
    fileinfo.update({
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "sha256": hashes["sha256"]
    })

    # peinfo = {}
    # docinfo = {}
    #
    # fileinfo.update({"docinfo": docinfo})
    # fileinfo.update({"peinfo": peinfo})

    function_size_list = nucleus.analysis(filename)

    if ispe(filename):
        pe = pefile.PE(filename)
        fileinfo.update({
            "imphash": pe.get_imphash(),
            "timestamp": datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S'),
            "dll": pe.FILE_HEADER.IMAGE_FILE_DLL,
            "imagebase": pe.OPTIONAL_HEADER.ImageBase,
            "entrypoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "behavior": yara_check.yara_match_from_file(
                path_to_file('antidebug_antivm.yar', 'signatures/yara_plugins/pe'), filename),
            "breakpoint": apialert.get_result(pe, load_config(path_to_file('stringsmatch.json', 'signatures'))[
                'breakpoint']),
            "metadata": meta.get(pe),
            "function_size": function_size_list
        })

        fileinfo.update(headers.get_dos_header(pe))
        fileinfo.update(headers.get_file_header(pe))
        fileinfo.update(headers.get_optional_header(pe))
        fileinfo.update(features.get_result(pe, filename))

        sections_dict = sections.get_result(pe)
        fileinfo.update({"section_count": sections_dict["count"], "section_details": sections_dict["details"]})

        strings_dict = fileurl.get_result(filename, load_config(path_to_file('stringsmatch.json', 'signatures')))
        fileinfo.update({
            "string_file": strings_dict["file"],
            "string_url": strings_dict["url"],
            "string_ip": strings_dict["ip"],
            "string_fuzzing": strings_dict["fuzzing"],
            "string_dump": strings_dict["dump"],
            "string_count": strings_dict["string_count"],
        })

        directories_dict = directories.get(pe)
        export_df = pd.DataFrame(directories_dict["export"])
        if not export_df.empty:
            export_df["function"] = export_df["function"].apply(lambda x: x.decode("utf-8") if x else None)

        fileinfo.update({
            "import": directories_dict["import"],
            "export": export_df.to_dict('records'),
            "debug": directories_dict["debug"],
            "tls": directories_dict["tls"],
            "resources": directories_dict["resources"],
            "relocations": directories_dict["relocations"],
            "sign": directories_dict["sign"]
        })

        fileinfo.update({"yara_plugins": yara_check.yara_match_from_folder(
            path_to_file('pe', 'signatures/yara_plugins'), filename, ['antidebug_antivm.yar'])})
    else:
        fileinfo.update({"docinfo": macro.get_result(filename)})
        fileinfo.update({"yara_plugins": yara_check.yara_match_from_folder(
            path_to_file('doc', 'signatures/yara_plugins'), filename)})

    dt_end = get_datetime_now()

    fileinfo.update({"time": str(dt_end - dt_start)})
    del fileinfo["e_res"]
    del fileinfo["e_res2"]
    return fileinfo
