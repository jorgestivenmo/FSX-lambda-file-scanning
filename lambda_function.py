import json
import boto3
import os
import base64
import smbclient
from botocore.exceptions import ClientError
from smbclient.path import (
    isdir,
)
import smbclient.shutil
import time
import amaas.grpc
import datetime



def lambda_handler(event, context):
    # Get the secret name from the environment variable
    fsxSecret = os.environ['SECRET_FSX']
    # Get a time variable to search the creation or modification date of the file
    # hour = int(os.environ['HOUR'])
    minutes = int(os.environ['MIN'])
    s3Bucketname = os.environ['QUARENTINE_BUCKET_NAME']
    startDate = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=minutes)
    endDate = datetime.datetime.now(datetime.UTC)
    startDate = startDate
    if os.environ['DELETE_FILES'] == 'true':
        deleteFilesFromFSx = True
    else:
        deleteFilesFromFSx = False
    maxSizeScannedFile = int(os.environ['MAX_SIZE_SCANNED_FILE'])  # MB
    
    # print(f"startDate: {startDate} endDate: {endDate}")
    
    # Get SMB Fileshare secret from AWS Secrets Manager 
    secret = get_secret(fsxSecret)

    # Parse JSON key value pairs.
    jsonString = json.loads(secret)
    username = jsonString["username"]
    password = jsonString["password"]
    host = jsonString["host"]
    destShare = jsonString["share"]
    apiKey = jsonString["apikeytrend"]
    region = jsonString["regiontrend"]
    
    s3 = boto3.client('s3') 
    
    
    # Construct default path for FSX:  
    destDirectoryPath = os.path.join(host, destShare)

    # Dict that contains fsx path, creation time, modification time 
    filesInfo = {}

    # Create a session to the server with explicit credentials
    try:
        smbclient.register_session(server=host, username=username, password=password)
        print("Samba session established")
    except Exception as err:
        print(f"Error establishing Samba session {err}")

    # Call scan_fsx_files 
    filesInfo = scan_fsx_files(destDirectoryPath, startDate, endDate, maxSizeScannedFile)
    
    # Create a session to the server with explicit credentials
    print("Configuring Vision One session")
    try:
        handle = amaas.grpc.init_by_region(region=region, api_key=apiKey)
        print("Vision One session established")
    except Exception as err:
        print(f"Error establishing Samba session {err}")

    # Call copy_file_to_tmp_folder_and_scan_it
    for k, v in filesInfo.items():
        copy_file_to_tmp_folder_and_scan_it(k, v, handle, s3Bucketname, s3, deleteFilesFromFSx)
    
    print("Successfully scanned files under {} folder from {} FSx!".format(destShare,host))

    smbclient.reset_connection_cache()
    print("Samba session closed")
    amaas.grpc.quit(handle)
    print("Vision One session closed")
    print("Lambda execution completed")
    return

# Function to scan the fsx and retrieves the information about files that were created or modified between the start and end date
def scan_fsx_files(destDirectoryPath, startDate, endDate, maxSizeScannedFile):
    directories = []
    oneMBinBytes = 1048576
    walkResults = smbclient.walk(destDirectoryPath)
    for dirpath, _, _ in walkResults:
        # print(f"\ndirPath: {dirpath}, dirNames: {dirnames}, fileNames: {filenames}\n")
        directories.append(dirpath)
    filesInfo = {}
    for directory in directories:
        for file_info in smbclient.scandir(directory):
            if file_info.is_file():
                fileName = file_info.name
                creationDate = file_info.smb_info.creation_time.replace(tzinfo=None)
                modificationDate = file_info.smb_info.last_write_time.replace(tzinfo=None)
                # print(f"File: {file_info.name} was created at {creationDate} and was modified at {modificationDate}")
                if startDate.timestamp() <= creationDate.timestamp() <= endDate.timestamp() or startDate.timestamp() <= modificationDate.timestamp() <= endDate.timestamp():
                    # print(f"The file {fileName} was created or modified between {startDate} and {endDate}")
                    if (file_info.smb_info.end_of_file / oneMBinBytes) > maxSizeScannedFile:
                        sizeFileInMB = file_info.smb_info.end_of_file / oneMBinBytes
                        print(f"The file {fileName} is bigger than {maxSizeScannedFile} MB -> [{round(sizeFileInMB,2)} MB], it will not be scanned")
                        continue
                    else:
                        if fileName not in filesInfo:
                            filesInfo[fileName] = {}
                            filesInfo[fileName]["path"] = file_info.path
                            filesInfo[fileName]["creation_time"] = file_info.smb_info.creation_time
                            filesInfo[fileName]["modification_time"] = file_info.smb_info.last_write_time
                            filesInfo[fileName]["size"] = file_info.smb_info.end_of_file
                            # print('Adding new File to dictionary: ', fileName)
                        else:
                            # print('File is already in dictionary: ', fileName)
                            continue
                else:
                    # print(f"The file {fileName} was not created or modified between {startDate} and {endDate}")
                    continue
            else:
                continue
    return filesInfo

# SMB file info response
# SMBDirEntryInformation(
#     creation_time=datetime.datetime(2024, 4, 19, 16, 57, 3, 549834, tzinfo=datetime.timezone.utc), 
#     last_access_time=datetime.datetime(2024, 4, 19, 16, 57, 3, 549834, tzinfo=datetime.timezone.utc), 
#     last_write_time=datetime.datetime(2024, 4, 19, 16, 47, 57, 459386, tzinfo=datetime.timezone.utc), 
#     change_time=datetime.datetime(2024, 4, 19, 16, 50, 41, 413197, tzinfo=datetime.timezone.utc), 
#     end_of_file=3056, 
#     allocation_size=3056, 
#     file_attributes=32, 
#     ea_size=0, 
#     file_id=281474976710699, 
#     file_name='deployment_workload.ps1'
#     )

# Funtion to copy the file to tmp folder and scan it with trend micro and return the results
def copy_file_to_tmp_folder_and_scan_it(fileName, fileParams, handle, bucketName, s3client, deleteFilesFromFSx):
    result = {}
    ErrorOpenFile = False
    try:
        f = smbclient.open_file(path=fileParams["path"],encoding="latin-1")
        data = f.read()
        f.close()
        f = open("/tmp/"+fileName, "w")
        f.write(data)
        f.close()
    except Exception as err:
        print(f"Error open file from fsx and store it in the tmp folder {err}")
        ErrorOpenFile = True
    # print(f"File {fileName} was copied into the tmp folder")

    if not ErrorOpenFile:
        # Set parameters for vision one scanning
        pml = True
        tags = [f"ScannDate: {datetime.datetime.now().date()}"]
        s = time.perf_counter()
        fileIsInfected = False
        
        try:
            r = amaas.grpc.scan_file(handle, file_name="/tmp/"+fileName, pml=pml, tags=tags)
            elapsed = time.perf_counter() - s
            # print(f"Scan executed in {elapsed:0.2f} seconds.")
            # print(f"Scann results: {r}")
            result = json.loads(r)
    
        except Exception as e:
            print(f"Error scanning file {e} ")
        if not result:
            print(f"Results Empty - there is an error scanning file {fileName}")
        else:
            if result['scanResult'] != 0:
                # print(f"File {fileName} is infected")
                fileIsInfected = True
                # print(f"The malwares founded are: {result['foundMalwares']}")
            else:
                # print(f"File {fileName} is clean")
                pass
        
        delete_file_from_tmp_folder(fileName, fileParams["path"], fileIsInfected, result, bucketName, s3client, deleteFilesFromFSx)
    else:
        print(f"There was an error copying the file {fileName} from FSx into /tmp dir")
    return

    # Scann results: 
    # {
    #     "scannerVersion": "1.0.0-31",
    #     "schemaVersion": "1.0.0",
    #     "scanResult": 0,
    #     "scanId": "8d38261b-a515-4488-9cc5-a43d5d0cf85d",
    #     "scanTimestamp": "2024-04-22T22:04:10.067Z",
    #     "fileName": "deployment_workload.ps1",
    #     "foundMalwares": [],
    #     "fileSHA1": "85fa5fbccd4dff211eb55e948851fab76424ee47",
    #     "fileSHA256": "0cbcd66380c75ed66ecce833e7cc9c5ca4b9f5d108d9a63205d04ec24c239132"
    # }

# Function to delete the file from the tmp folder and add a TODO to open different ways to do something before deleting the file
def delete_file_from_tmp_folder(fileName, filePath, fileIsInfected, result, bucketName, s3client, deleteFilesFromFSx):

    # TODO add a function to do something before deleting the file
    # This action could be to send the file to a bucket or to another folder on fsx or send it to a quarantine
    if fileIsInfected:
        print(f"File {fileName} is infected, the file will be sent into quarantine, results: {result}")
        # TODO send file to quarantine
        if deleteFilesFromFSx:
            smbclient.remove(filePath)
            print(f'The file {fileName} was removed from FSx {filePath}')
        if bucketName != '':
            s3client.upload_file(Filename=str('/tmp/'+fileName), Bucket=bucketName, Key=fileName)
            print(f'The file {fileName} was sent into quarantine bucket')
        else:
            print(f"The file {fileName} was removed from FSx {filePath}")

    # Removing file from tmp dir
    try:
        os.remove("/tmp/"+fileName)
    except Exception as e:
        print(f"Error deleting file {e} ")
    # print(f"File {fileName} was deleted from the tmp folder")
    


def get_secret(secret_name):

    region_name = os.environ['AWS_REGION']

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )

    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret