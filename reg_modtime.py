import winreg
import argparse
from datetime import datetime, timezone
import sys
# Modified function from
# https://github.com/jleclanche/winfiletime/blob/master/winfiletime/filetime.py
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as filetime
HUNDREDS_OF_NS = 10000000

def to_datetime(filetime: int, use_local_timezone: bool = False) -> datetime:
    """
    Converts a Windows filetime number to a Python datetime.
    If use_local_timezone is True, the datetime object will be in the local timezone.
    Otherwise, it will be timezone-naive but is equivalent to tzinfo=utc.
    """
    # Get seconds and remainder in terms of Unix epoch
    s, ns100 = divmod(filetime - EPOCH_AS_FILETIME, HUNDREDS_OF_NS)
    # Convert to datetime object, with remainder as microseconds.
    dt_utc = datetime.fromtimestamp(s, tz=timezone.utc).replace(microsecond=(ns100 // 10))

    if use_local_timezone:
        return dt_utc.astimezone()
    return dt_utc



def get_regkey_last_mtime(key_path: str, use_local_timezone: bool = False):
    '''Returns the last modified datetime of a given registry key path.'''
    # try:
        # Define a dictionary to map keywords to hives
    hive_map = {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKU": winreg.HKEY_USERS,
        "HKEY_USERS": winreg.HKEY_USERS,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        "HKCC": winreg.HKEY_CURRENT_CONFIG,
        "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG
    }

    # Set the default hive as None
    hive = None
    key_path = key_path.upper() # set case insensitive
    # check for hive keywords
    for keyword, hive_value in hive_map.items():
        if keyword in key_path:
            hive = hive_value
            break

    # If no matching hive is found
    if hive is None:
        print(f"Unsupported registry hive in the key path: {key_path}")
        return None

    # Replace any escaped backslashes with a single backslash
    if "\\\\" in key_path:
        key_path = key_path.replace("\\\\", "\\")

    # Remove hive
    for keyword in hive_map.keys():
        key_path = key_path.replace(f"{keyword}\\", "")

    # Open the registry key
    key = winreg.OpenKey(hive, key_path)
    last_modified_time = winreg.QueryInfoKey(key)
    last_modified_time = to_datetime(last_modified_time[2], use_local_timezone)
    return last_modified_time


def read_kpaths_from_file(file_path:str)->list:
    '''Returns key path(s) from a text file'''
    try:
        with open(file_path, 'r') as file:
            key_paths = [line.strip() for line in file if line.strip()] # ignore empty lines
        return key_paths
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Query the modification time of Windows Registry keys.")
    parser.add_argument("KEY_PATHS", nargs='*', help="Absolute paths to the registry keys.")
    parser.add_argument("-l", "--local", action="store_true", help="Display result in local timezone. If the flag is not set, displays in UTC +00:00")
    parser.add_argument("-r", "--read-file", help="Read key paths from a text file (one path per line).")
    key_args = parser.parse_args()
    use_local_timezone = key_args.local

    if key_args.read_file:
        key_paths = read_kpaths_from_file(key_args.read_file)
    else:
        key_paths = key_args.KEY_PATHS
    try:
        for key_path in key_paths:
            last_mtime = get_regkey_last_mtime(key_path, use_local_timezone)
            if last_mtime:
                print(f"{key_path}\n{last_mtime}")
                print("===================================================")

    except FileNotFoundError:
        print(f"Error: The system cannot find the specified registry key:{key_path}")
    except Exception as e:
        print(f"Error occurred for key path {key_path}: {e}")

if __name__ == "__main__":
    main()