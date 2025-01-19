import os
import logging

def file_exists(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"The file '{file_path}' does not exist.")
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Insufficient permission to read '{file_path}'.")
    logging.debug(f"Successful file verification : {file_path}")
