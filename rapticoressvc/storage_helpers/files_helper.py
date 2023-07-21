import json
import logging
import os
import shutil
from enum import Enum


class FileFormat(Enum):
    JSON = "json"


def check_directory(destination):
    directory_exists = False
    try:
        if destination:
            destination = destination if type(destination) is list else [destination]
            directory_destination_path = get_system_path_to_file_destination(destination)
            if os.path.exists(directory_destination_path):
                directory_exists = True
    except Exception as e:
        logging.exception(e)
    return directory_exists


def set_directory(destination):
    try:
        if destination:
            destination = destination if type(destination) is list else [destination]
            directory_destination_path = get_system_path_to_file_destination(destination)
            if os.path.exists(directory_destination_path):
                shutil.rmtree(directory_destination_path)
            os.makedirs(directory_destination_path, exist_ok=True)
    except Exception as e:
        logging.exception(e)


def get_system_path_to_file_destination(file_destination, start_location=None):
    file_destination_path = None
    try:
        if file_destination:
            file_destination = file_destination if type(file_destination) is list else [file_destination]
            if all(isinstance(sub_path, str) for sub_path in file_destination):
                file_destination_path = start_location or "."  # starting point
                non_path_slash_signature = ':slash:'
                for sub_path in file_destination:
                    file_destination_path = os.path.join(str(file_destination_path),
                                                         str(sub_path).replace('/', non_path_slash_signature))
    except Exception as e:
        logging.exception(e)
    return file_destination_path


def save_to_file(data, file_destination, file_format, mode=None, create_path_to_file=True, start_location=None):
    success_flag = False
    try:
        if create_path_to_file and type(file_destination) is list and len(file_destination) > 1:
            directory_destination = file_destination[:-1]
            not check_directory(directory_destination) and set_directory(directory_destination)

        file_destination_path = get_system_path_to_file_destination(file_destination, start_location=start_location)
        if data and file_destination_path:
            os.path.isfile(file_destination_path) and logging.warning(f'Replacing file: {file_destination_path}')
            module = None
            if file_format == FileFormat.JSON.value:
                module = json
            mode = mode or 'w'
            with open(file_destination_path, mode) as file:
                module.dump(data, file)
                file.close()
                success_flag = True
    except Exception as e:
        logging.exception(e)
    return success_flag


def save_to_json_file(data, file_destination, mode=None, start_location=None):
    return save_to_file(data, file_destination, FileFormat.JSON.value, mode=mode, start_location=start_location)


def read_from_file(file_destination, file_format: FileFormat, mode=None, start_location=None):
    data = None
    try:
        file_destination_path = get_system_path_to_file_destination(file_destination, start_location=start_location)
        if file_destination_path and os.path.exists(file_destination_path):
            module = None
            if file_format == FileFormat.JSON.value:
                module = json
            mode = mode or 'r'
            with open(file_destination_path, mode) as file:
                data = module.load(file)
    except Exception as e:
        logging.exception(e)
    return data


def read_from_json_file(file_destination, mode=None, start_location=None):
    return read_from_file(file_destination, FileFormat.JSON.value, mode, start_location)
