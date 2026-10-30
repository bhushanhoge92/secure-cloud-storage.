
import os
import json
import base64
import uuid
import boto3
import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AWS configuration
BUCKET_NAME = "bhushan-secure-cloud-2025"
BLOCK_SIZE = 1024 * 1024  # 1 MB

s3 = boto3.client(
    "s3",
    aws_access_key_id=st.secrets["aws"]["access_key_id"],
    aws_secret_access_key=st.secrets["aws"]["secret_access_key"],
    region_name=st.secrets["aws"]["region"]
)


def encrypt_file(file_data):
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)

    encrypted_data = aes.encrypt(nonce, file_data, None)
    return key, nonce, encrypted_data


def upload_blocks(encrypted_data, file_id):
    blocks = [
        encrypted_data[i:i + BLOCK_SIZE]
        for i in range(0, len(encrypted_data), BLOCK_SIZE)
    ]

    uploaded_keys = []

    for index, block in enumerate(blocks):
        object_key = f"encrypted/{file_id}/block_{index + 1:04d}.bin"

        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=object_key,
            Body=block
        )

        uploaded_keys.append(object_key)

    return uploaded_keys


st.set_page_config(page_title="Secure Cloud Storage", page_icon="🔐")

st.title("🔐 Secure Cloud File Storage")
st.write("Encrypt files, split them into 1 MB blocks, and store them in AWS S3.")

uploaded_file = st.file_uploader("Choose a file")

if uploaded_file and st.button("Encrypt and Upload"):
    try:
        original_data = uploaded_file.getvalue()
        file_id = str(uuid.uuid4())

        key, nonce, encrypted_data = encrypt_file(original_data)
        uploaded_keys = upload_blocks(encrypted_data, file_id)

        # Save the key and metadata for the later download/decryption step.
        # Keep this information private; it is required to decrypt the file.
        metadata = {
            "file_name": uploaded_file.name,
            "file_id": file_id,
            "key": base64.b64encode(key).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "blocks": uploaded_keys
        }

        st.session_state["last_metadata"] = metadata

        st.success("File encrypted and uploaded successfully!")
        st.write(f"Original file size: {len(original_data):,} bytes")
        st.write(f"Encrypted size: {len(encrypted_data):,} bytes")
        st.write(f"Number of blocks uploaded: {len(uploaded_keys)}")
        st.code(file_id)

        st.warning(
            "Keep the decryption key and metadata safe. "
            "They are currently stored only in this running session."
        )

    except Exception as error:
        st.error(f"Operation failed: {error}")

def download_and_decrypt(metadata):
    # Download all encrypted blocks in the correct order
    encrypted_data = b""

    for object_key in metadata["blocks"]:
        response = s3.get_object(
            Bucket=BUCKET_NAME,
            Key=object_key
        )
        encrypted_data += response["Body"].read()

    # Decode the saved encryption key and nonce
    key = base64.b64decode(metadata["key"])
    nonce = base64.b64decode(metadata["nonce"])

    # Decrypt the reconstructed data
    aes = AESGCM(key)
    original_data = aes.decrypt(nonce, encrypted_data, None)

    return original_data

st.divider()
st.subheader("Download and Decrypt File")

metadata = st.session_state.get("last_metadata")

if metadata:
    if st.button("Download and Decrypt"):
        try:
            original_data = download_and_decrypt(metadata)

            st.download_button(
                label="Save Original File",
                data=original_data,
                file_name=metadata["file_name"],
                mime="application/octet-stream"
            )

            st.success("File recovered successfully!")

        except Exception as error:
            st.error(f"Download failed: {error}")
else:
    st.info("Upload a file first in this running session.")

