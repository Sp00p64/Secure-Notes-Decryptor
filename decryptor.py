import sqlite3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import argparse
import os.path
def derive_key(password, crypto_salt, crypto_iterations):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,  # Apple uses 16-byte keys
        salt=crypto_salt,
        iterations=crypto_iterations,
    )
    key = kdf.derive(password)
    return key

def unwrap_key(wrapped_key, key_encrypting_key):
    return keywrap.aes_key_unwrap(key_encrypting_key, wrapped_key)


def decrypt_aes_gcm(key, iv, tag, data):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    plaintext = decryptor.update(data) + decryptor.finalize()
    return plaintext

# Method to write binary data to a file
def write_binary_to_file(filename, data):
    with open(filename, 'wb') as file:
        file.write(data)


def fetch_table_data(cursor, table_name):
    """Fetch all rows from a table and return them as a list of dictionaries."""
    cursor.execute(f"SELECT * FROM {table_name}")
    column_names = [description[0] for description in cursor.description]
    rows = cursor.fetchall()
    return [dict(zip(column_names, row)) for row in rows]

def find_encryption_attributes(rows):
    """Find encryption attributes in password-protected notes."""
    for row in rows:
        if row.get("ZISPASSWORDPROTECTED") == 1:
            print("[*] Found a password-protected note!")
            required_fields = {
                "IV": row.get("ZCRYPTOINITIALIZATIONVECTOR"),
                "salt": row.get("ZCRYPTOSALT"),
                "tag": row.get("ZCRYPTOTAG"),
                "iteration count": row.get("ZCRYPTOITERATIONCOUNT"),
                "Wrapped Key": row.get("ZCRYPTOWRAPPEDKEY")
            }
            missing_fields = [name for name, value in required_fields.items() if value is None]

            if missing_fields:
                print(f"[!] Missing {', '.join(missing_fields)}; cannot continue decryption.")
                return None
            else:
                return (
                    required_fields["IV"],
                    required_fields["salt"],
                    required_fields["tag"],
                    required_fields["iteration count"],
                    required_fields["Wrapped Key"],
                )
    print("[!] No password-protected notes found.")
    return None

def main(password,database_path):
    if not os.path.exists(database_path):
        print(f"[!] File {database_path} does not exist!")
        exit()
    notes_details_table = 'ZICCLOUDSYNCINGOBJECT'
    notes_content_table = 'ZICNOTEDATA'

    # Connect to the SQLite database
    conn = sqlite3.connect(database_path)
    try:
        cursor = conn.cursor()

        # Fetch notes details
        notes_details = fetch_table_data(cursor, notes_details_table)
        attributes = find_encryption_attributes(notes_details)

        if attributes:
            iv, salt, tag, iteration_count, wrapped_key = attributes
            print(f"[*] Found IV: {iv}")
            print(f"[*] Found salt: {salt}")
            print(f"[*] Found tag: {tag}")
            print(f"[*] Found wrapped key: {wrapped_key}")
            print(f"[*] Found iteration count: {iteration_count}")
            # Fetch notes content
            notes_content = fetch_table_data(cursor, notes_content_table)
            for row in notes_content:
                if row.get('ZDATA') is not None:
                    encrypted_data = row['ZDATA']
                    print("[*] Found content data!")
                    print("[*] Deriving key...")
                    key_encrypting_key = derive_key(bytes(password,encoding='utf-8'),salt,iteration_count)
                    print("[*] Unwrapping key....")
                    try:
                        unwrapped_key = unwrap_key(wrapped_key, key_encrypting_key)
                    except:
                        print("[!] Unwrapping failed... Wrong password ?")
                        exit()
                    print("[*] Attempting decryption....")
                    plaintext = decrypt_aes_gcm(unwrapped_key, iv, tag, encrypted_data)
                    write_binary_to_file('decrypted_output.bin', plaintext)
                    print("[*] Data written to decrypted_output.bin")
            exit()
    finally:
        conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("IOS Secure note decryptor")
    parser.add_argument("--password", help="Password used to encrypt the note.", type=str,required=True)
    parser.add_argument("--path", help="Path to NoteStore.sqlite file", type=str,required=True)
    args = parser.parse_args()
    main(args.password,args.path)
