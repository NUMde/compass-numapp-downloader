import config as CONFIG  # configuration file

import base64
import datetime
from jose import jws
from jose.constants import ALGORITHMS
import json
from M2Crypto import BIO, EVP, SMIME, Rand, RSA
import os
import pandas as pd
import pytz
import requests
import sys
from typing import List, Tuple

# remove _DEV to change to PROD environment
BASE_URL = CONFIG.BASE_URL_DEV

# ######################### EN-/ DECRYPTION #########################


def initialize_decryption_key_object() -> SMIME:
    """Initialize SMIME object with loaded keys for decryption purposes.

    Returns
    -------
    s: SMIME
        SMIME object with loaded private key and certificate.

    """

    s = SMIME.SMIME()
    s.load_key(CONFIG.PRIV_KEY, CONFIG.CERT)

    return s


def initialize_sig_verification_key() -> str:
    """Load sender public key from file.

    Returns
    -------
    sender_public_key: str
        Content of public sender key file.

    """

    f = open(CONFIG.PUB_KEY_SENDER, "r")
    sender_public_key = f.read()
    f.close()

    return sender_public_key


def aes_encrypt(data: str) -> Tuple[str, str, str]:
    """Encrypt a value with aes_256_cbc.

    Parameters
    data : str
        Base64 encoded value for encryption.

    Returns
    ----------
    base64_key : str
        Base64 encoded key for encryption.
    base64_iv : str
        Base64 encoded initialization vector.
    base64_cipher : str
        Base64 encoded cipher.

    """
    iv = Rand.rand_bytes(16)
    key = Rand.rand_bytes(32)

    cipher = EVP.Cipher(alg="aes_256_cbc", key=key, iv=iv, op=1)
    cipher_text = cipher.update(base64.b64decode(data))
    cipher_text = cipher_text + cipher.final()

    base64_cipher = base64.b64encode(cipher_text).decode("utf-8")
    base64_key = base64.b64encode(key).decode("utf-8")
    base64_iv = base64.b64encode(iv).decode("utf-8")

    return base64_key, base64_iv, base64_cipher


def rsa_encrypt(data: str) -> str:
    """Encrypt a string value with RSA PKCS#1.

    Parameters
    ----------
    data : str
        Base64 encoded value for encryption.

    Note
    ----
    Function uses global CONFIG values for:
        PUB_KEY_SENDER
            Path to public key file.


    Returns
    -------
    base64_cipher : str
        Base64 encoded cipher.

    """
    public_key = RSA.load_pub_key(CONFIG.PUB_KEY_SENDER)
    cipher_text = public_key.public_encrypt(
        base64.b64decode(data.encode("utf-8")), RSA.pkcs1_padding
    )
    base64_cipher = base64.b64encode(cipher_text).decode("utf-8")

    return base64_cipher


def pkcs7_decrypt(data: bytes) -> str:
    """Decrypt a bytes string with RSA PKCS#7.

    Parameters
    ----------
    data : bytes
        Base64 bytes string to be decrypted.

    Note
    ----
    Function uses global CONFIG values for:
        PRIV_KEY
            Path to private key file.
        CERT
            Path to certificate file.

    Function uses global value for:
        SMIME_OBJ
            Globally initialized SMIME object with loaded keys.

    Returns
    -------
    plain_text : str
        Decrypted text. None if decryption was not successful.

    """

    try:
        pkcs7_string = "-----BEGIN PKCS7-----\n" + data + "\n-----END PKCS7-----"
        bio = BIO.MemoryBuffer(pkcs7_string.encode("ascii"))
        smime_object = SMIME.load_pkcs7_bio(bio)

        out = SMIME_OBJ.decrypt(smime_object)
        plain_text = out.decode()
    except:
        plain_text = None

    return plain_text


def verify_signature(jws_token: bytes) -> str:
    """Verify RSA SHA 256 signature.

    Parameters
    ----------
    jws_token : bytes
        Token including payload and signature.

    Note
    ----
    Function uses global CONFIG values for:
        PUB_KEY_SENDER
            Path to sender's public key file.

    Function uses global value for:
        SIG_VERIFICATION_KEY
            Globally initialized public sender key.

    Returns
    -------
    payload: str
        Verified payload contained in token.

    """

    try:
        payload = jws.verify(
            jws_token, SIG_VERIFICATION_KEY, algorithms="RS256")
        return payload.decode()
    except Exception as err:
        return None


# ######################### QUEUE OPERATIONS #########################


def get_authentication_token() -> str:
    """Get authentication token to  enable authenticated requests to mobile backend.

    Note
    ----
    Function uses global CONFIG values for:
        API_ID
            Identification of client for retrieval of authentication token
        API_KEY
            Secret of client for retrieval of authentication token
        BASE_URL
            URL for mobile backend.
        AUTH_ROUTE
            Authentication route name.


    Returns
    -------
    token : str
        Access token for further requests to mobile backend.

    """

    current_date_time = datetime.datetime.now(
        pytz.timezone('Europe/Berlin')).strftime("%m/%d/%Y %H:%M:%S")
    auth_creds = {
        "ApiID": CONFIG.API_ID,
        "ApiKey": CONFIG.API_KEY,
        "CurrentDate": current_date_time,
    }

    try:
        key, iv, aes_encrypted_auth_creds = aes_encrypt(
            base64.b64encode(json.dumps(auth_creds).encode())
        )
        rsa_encrypted_aes_key = rsa_encrypt(key)
        auth_body = {
            "encrypted_creds": aes_encrypted_auth_creds,
            "encrypted_key": rsa_encrypted_aes_key,
            "iv": iv,
        }
        response = requests.post(
            url=BASE_URL + "/" + CONFIG.AUTH_ROUTE, data=auth_body)
        token = json.loads(response.text)["access_token"]
        response.raise_for_status()
    except Exception as err:
        if response and response.status_code != 200:
            sys.exit(str(response.status_code) + " - " + str(response.reason))
        else:
            sys.exit(err)
    return token


def get_page(headers: str, page: int) -> dict:
    """Download data from queue by page.

    Parameters
    ----------
    headers : str
        Request headers including authentication token.

    page : int
        Page for which data should be retrieved.

    Note
    ----
    Function uses global CONFIG values for:
        DL_ROUTE:
            Questionnaire response download route name.

    Returns
    -------
    result : dict
        Response dictionary containing data for requested page.

    """

    qr_route = BASE_URL + "/" + CONFIG.DL_ROUTE
    params = {"page": page}
    try:
        response = requests.get(url=qr_route, headers=headers, params=params)
        response.raise_for_status()
    except Exception as err:
        if response.status_code != 200:
            sys.exit(str(response.status_code) + " - " + str(response.reason))
        else:
            sys.exit(err)
    result = json.loads(response.text)

    return result


def get_qr_list_from_queue(headers: str) -> pd.DataFrame:
    """Get all questionnaire response objects currently available in database queue.

    Parameters
    ----------
    headers : str
        Request headers including authentication token.

    Note
    ----
    Function uses global CONFIG values for:
        INT_RESULT_PATH
            Path to file for logging of result.

    Returns
    -------
    qr_list_df : pd.DataFrame
        Dataframe containing all retrieved questionnaire response objects in encrypted form as well as their signature and corresponding metadata.

    """

    response_msg_initial = get_page(headers, 1)
    total_pages = response_msg_initial["totalPages"]
    qr_list_df = verify_and_parse_result(response_msg_initial["cTransferList"])

    # get all remaining pages
    for page in range(2, total_pages + 1):
        response_msg = get_page(headers, page)
        df_to_add = verify_and_parse_result(
            response_msg_initial["cTransferList"])
        qr_list_df = qr_list_df.append(df_to_add, sort=False)

    write_df_to_file(
        CONFIG.INT_RESULT_PATH,
        "w+",
        qr_list_df,
    )

    return qr_list_df


def update_entries(headers: str, uuids: List[str]) -> dict:
    """Update all questionnaire response objects that were downloaded from queue.

    Parameters
    ----------
    headers : str
        Request headers including authentication token.
    uuids : List[str]
        List of IDs that identify database entries that should be marked as downloaded.

    Note
    ----
    Function uses global CONFIG values for:
        DL_ROUTE:
            Questionnaire response download route name.

    Returns
    -------
    result : dict
        Response dictionary containing info on updated entries.

    """

    qr_route = BASE_URL + "/" + CONFIG.DL_ROUTE

    try:
        response = requests.put(url=qr_route, headers=headers, json=uuids)
        result = json.loads(response.text)
        response.raise_for_status()
    except Exception as err:
        if response.status_code != 200:
            sys.exit(str(response.status_code) + " - " + str(response.reason))
        else:
            sys.exit(err)
    return result


# ########################## UTIL OPERATIONS ##########################


def write_df_to_file(path: str, mode: str, df: pd.DataFrame) -> bool:
    """Write content of dataframe to text file in csv format.

    Parameters
    ----------
    path : str
        Path to output file.
    mode : str
        Write mode (e.g. r, w, a ...).
    df : pd.DataFrame
        Dataframe that is written to file.

    Returns
    -------
    bool
        True if successful, False otherwise.

    """

    try:
        filename, file_extension = os.path.splitext(path)
        if file_extension == '':
            file_extension = '.txt'
        time = str(datetime.datetime.now(pytz.timezone(
            'Europe/Berlin')).strftime("_%d_%m_%Y_%H_%M_%S"))
        file_out = open(filename + time + file_extension, mode)
        file_out.write(df.to_csv(index=False))
    except:
        print("Dataframe could not be written to file. Printing here instead:\n")
        print(df.to_csv(index=False))
        return False
    return True


def verify_and_parse_result(jws_token: bytes) -> pd.DataFrame:
    """Verify JWS token and transform payload into dataframe.

    Parameters
    ----------
    jws_token : bytes
        JWS token to be verified.

    Returns
    -------
    payload_df: pd.DataFrame
        Dataframe representing payload of JWA token is  empty when signature is invalid.

    """

    payload = verify_signature(jws_token)
    if payload != None:
        payload_df = pd.DataFrame(eval(payload))
    else:
        print("Invalid signature detected! Ignoring corresponding response objects.")
        payload_df = pd.DataFrame()
    return payload_df


if __name__ == "__main__":
    SMIME_OBJ = initialize_decryption_key_object()
    SIG_VERIFICATION_KEY = initialize_sig_verification_key()

    print("\n########## (1/5) Getting authentication token")
    token = get_authentication_token()
    headers = {"Authorization": CONFIG.AUTH_TYPE + " " + token}

    print("\n########## (2/5) Getting pages from queue")
    result_df = get_qr_list_from_queue(headers)
    if result_df.empty:
        sys.exit(
            'No questionnaire responses were submitted since the last retrieval. Finishing script.')

    print("\n########## (3/5) Decrypting verified questionnaire response objects")
    result_df["JSON"] = result_df["JSON"].map(pkcs7_decrypt)
    not_decryptable_objects = result_df[result_df["JSON"].isna(
    )]["UUID"].tolist()
    if len(not_decryptable_objects) > 0:
        print(
            "Response objects with following UUID values could not be decrypted: \n%s "
            % (not_decryptable_objects)
        )

    print(
        "\n########## (4/5) Writing decrypted response objects to: %s "
        % (CONFIG.RESULT_PATH)
    )
    write_df_to_file(
        CONFIG.RESULT_PATH,
        "w+",
        result_df.loc[
            result_df["JSON"].notna(),
            ["UUID", "AppId", "JSON", "AbsendeDatum", "ErhaltenDatum"],
        ],
    )

    print("\n########## (5/5) Updating all decrypted questionnaire response objects")
    result = update_entries(
        headers, result_df[result_df["JSON"].notna()]["UUID"].tolist()
    )
    if result["updatedRowCount"]:
        print("Updated %s objects" % (result["updatedRowCount"]))
    else:
        print("Nothing to update")
