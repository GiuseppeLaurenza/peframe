import pefile


def get_optional_header(pe):
    result_dict = {}
    try:
        for i in range(0, len(pe.OPTIONAL_HEADER.__keys__)):
            result_dict[pe.OPTIONAL_HEADER.__keys__[i][0]] = pe.OPTIONAL_HEADER.__unpacked_data_elms__[i]
    except:
        pass
    return result_dict


def get_file_header(pe):
    result_dict = {}
    try:
        for i in range(0, len(pe.FILE_HEADER.__keys__)):
            result_dict[pe.FILE_HEADER.__keys__[i][0]] = pe.FILE_HEADER.__unpacked_data_elms__[i]
    except:
        pass
    return result_dict


def get_dos_header(pe):
    result_dict = {}
    try:
        for i in range(0, len(pe.DOS_HEADER.__keys__)):
            result_dict[pe.DOS_HEADER.__keys__[i][0]] = pe.DOS_HEADER.__unpacked_data_elms__[i]
    except:
        pass
    return result_dict


def get_rich_header(pe):
    result_dict = {}
    try:
        for i in range(0, len(pe.RICH_HEADER.__keys__)):
            result_dict[pe.RICH_HEADER.__keys__[i][0]] = pe.RICH_HEADER.__unpacked_data_elms__[i]
    except:
        pass
    return result_dict

def get_vs_fixedfileinfo(pe):
    result_dict = {}
    try:
        for i in range(0, len(pe.VS_FIXEDFILEINFO.__keys__)):
            result_dict[pe.VS_FIXEDFILEINFO.__keys__[i][0]] = pe.VS_FIXEDFILEINFO.__unpacked_data_elms__[i]
    except:
        pass
    return result_dict

def get_fileinfo(pe):
    result_dict = {}
    try:
        if hasattr(pe, 'VS_VERSIONINFO'):
            if hasattr(pe, 'FileInfo'):
                for entry in pe.FileInfo:
                    if hasattr(entry, 'StringTable'):
                        for st_entry in entry.StringTable:
                            result_dict = st_entry.entries
    except:
        pass
    return result_dict

'''
path = '/Users/garage131/Downloads/pafish.exe'

pe = pefile.PE(path)
test = {}
result = get_fileinfo(pe)
#print sections
#print pe.dump_dict()
print result
'''