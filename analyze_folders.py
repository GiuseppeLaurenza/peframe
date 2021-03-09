
import logging
import os
import shutil
from json import JSONDecodeError
from multiprocessing import Pool, cpu_count, current_process
import json

from peframe.peframe import analyze

LOGGER = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s')


def analysis_to_json(arguments):
    try:
        filename = arguments[0]
        outputfile = arguments[1]
        if filename is None:
            raise Exception("Missing Filename")
        LOGGER.info("[" + str(current_process()) + "] Analysing file " + filename)
        features = analyze(filename)
        if outputfile is not None:
            LOGGER.info("[" + str(current_process()) + "] Writing file of " + outputfile)
            with open(outputfile, 'w') as fp:
                json.dump(features, fp)
        return features
    except Exception as e:
        print("Impossible to analyze " + filename)
        print(e)
        if "non_apt" in filename:
            dest = "/home/giuseppe/binaries/problematic_non_apt/"
        else:
            dest = "/home/giuseppe/binaries/problematic_apt/"
        shutil.move(filename, dest+os.path.basename(filename))


def check_file(path):
    try:
        with open(path, "r") as inputfile:
            json.load(inputfile)
    except JSONDecodeError:
        os.remove(path)

def check_analysis_list(analysis_folder):
    list_file = [analysis_folder + x for x in os.listdir(analysis_folder)]
    pool = Pool(cpu_count()-2)
    pool.map(check_file, list_file)

def analyze_folder(binary_folder, analysis_folder, parallel=True):
    LOGGER.info("Analyzing folder "+binary_folder)
    filename_list = os.listdir(binary_folder)
    check_analysis_list(analysis_folder)
    analysis_list = os.listdir(analysis_folder)
    clean_analyis_list = [x[:-len(".json")] for x in analysis_list]
    to_analyze = [item for item in filename_list if item not in clean_analyis_list]
    arguments_list = [(binary_folder + x, analysis_folder + x + ".json") for x in to_analyze]

    if parallel:
        pool = Pool(processes=cpu_count() - 2)
        pool.map(analysis_to_json, arguments_list)
    else:
        for argument in arguments_list:
            analysis_to_json(argument)

def main():

    binary_folder = "/home/giuseppe/binaries/apt/"
    result_folder = "/home/giuseppe/analysis/apt/"
    analyze_folder(binary_folder, result_folder, True)

    binary_folder = "/home/giuseppe/binaries/non_apt/"
    result_folder = "/home/giuseppe/analysis/non_apt/"
    analyze_folder(binary_folder, result_folder, True)


main()


# path = "/home/giuseppe/binaries/problematic_apt/b8e728703604afde97716309b260a611"
# dest = "/tmp/1.json"
# analysis_to_json((path, dest))
