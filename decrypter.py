import base64

def xor_encrypt_decrypt(text, key):
    encrypted_text = ""
    for i in range(len(text)):
        encrypted_text += chr(ord(text[i]) ^ ord(key[i % len(key)]))
    return encrypted_text

def encrypt_message():
    try:
        key = "secretkey"
        message = input("Enter your message: ")

        if not message:
            raise ValueError("Message cannot be empty.")

        
        encrypted_message = xor_encrypt_decrypt(message, key)

        
        encoded_message = base64.b64encode(encrypted_message.encode()).decode()

        print("Encrypted Message (Base64):", encoded_message)

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    encrypt_message()
