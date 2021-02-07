#import for 1) Fernet
from cryptography.fernet import Fernet

#import for 2) SimpleCrypt
from simplecrypt import encrypt, decrypt

#import for 3) Hashlib MD5 and SHA1
import hashlib

class Crypto_fernet:
  #each instance of class should create a new key
  def __init__(self):
    #init key here if you want the key to generate each time
    #self.key = Fernet.generate_key()
    pass

  #getter and setter
  def get_key(self):
    return self.key
  def set_key(self, key):
    self.key = key
  
  def gen_key(self):
    self.set_key(Fernet.generate_key())


  #writing key to a file
  def fernet_write_key(self):
      #key = Fernet.generate_key()
      with open("key2.key", "wb") as key_file:
          key_file.write(self.get_key())

  # Function to load the key from file
  def fernet_read_key(self):
    return open("key2.key", "rb").read()

  #returns message encrypt
  def fernet_encrypt(self, msg_plain):
    self.set_key(self.fernet_read_key())
    msg_encoded = msg_plain.encode()
    
    fern_a = Fernet(self.get_key())
    msg_encrypted = fern_a.encrypt(msg_encoded)

    return msg_encrypted
  
  #returns message decrpyted
  def fernet_decrpyt(self, msg_encrypt):
    self.set_key(self.fernet_read_key())
    fernet_b = Fernet(self.get_key())
    
    msg_decrypted = fernet_b.decrypt(msg_encrypt)
    
    return msg_decrypted

class Crpto_simple:
  #init
  def __init__(self, msg):
    self.msg = msg
  
  #getter and setter
  def get_msg(self):
    return self.msg
  def set_msg(self, msg):
    self.msg = msg

  def simple_encrypt(self, pw):
    return encrypt(pw, self.get_msg())
  
  def simple_decrypt(self, pw, msg_crypt):
    return decrypt(pw, msg_crypt)

  def webcode():
    message = "Hello!! Welcome to AIM!!"
    ciphercode = encrypt('AIM', message)
    print(ciphercode)

    #---
    original = decrypt('AIM', ciphercode)
    print(original)

    #Py3 the outputs from encrypt and decrypt are bytes. If you started with string input then you can convert the output from decrypt using .decode('utf8'):

    #mystring = decrypt('password', ciphertext).decode('utf8')

class Crypto_md5:
  def __init__(self, msg):
    self.msg = msg
  
  def get_msg(self):
    return self.msg
  def set_msg(self, msg):
    self.msg = msg
  
  def md5_encrypt(self):
    msg_encoded = str.encode(self.get_msg())
    msg_hash_md5 = hashlib.md5(msg_encoded)
    converted = msg_hash_md5.hexdigest()

    return converted

class Crypto_sha1:
  def __init__(self, msg):
    self.msg = msg

  def get_msg(self):
    return self.msg
  def set_msg(self, msg):
    self.msg = msg

  def sha1_encrypt(self):
    msg_encoded = str.encode(self.get_msg())
    msg_hash_sha1 = hashlib.sha1(msg_encoded)
    converted = msg_hash_sha1.hexdigest()
    
    return converted


#---------------------------------------------------
def main():
  #FERNET ENCRYPTION TEST
  print("Fernet Encryption")
  fernet1 = Crypto_fernet()

  fernet1.gen_key()
  fernet1.fernet_write_key()

  read_key = fernet1.fernet_read_key()
  print("Fernet Key: ", read_key)
  fern_msg_encrypt = fernet1.fernet_encrypt("hi")
  print("Fernet Encrypted Msg: ", fern_msg_encrypt)

  fern_msg_decrypt = fernet1.fernet_decrpyt(fern_msg_encrypt)
  print("Fernet Decrypted Msg: ", fern_msg_decrypt)
  print("\n")

  #SIMPLE CRYPTO
  #   #ran into error with simple crypt.
  #simple1 = Crpto_simple("ucsd")

  #   #time.clock creating error in a package. IS SOMETHING Depricated???
  #simp_msg_encrypt = simple1.simple_encrypt(1234)
  #print("Simple Encrypted Msg: ", simp_msg_encrypt)

  #simp_msg_decrypt = simple1.simple_decrypt("1234", simp_msg_encrypt)
  #print("Simple Decrypted Msg: ", simp_msg_decrypt)

  #MD5 HASH TEST
  print("MD5 Hash")
  md5_1 = Crypto_md5("ucsd")
  md5_msg_encrypt = md5_1.md5_encrypt()
  print("MD5 Msg:", md5_1.get_msg())
  print("MD5 Encrypted Msg:", md5_msg_encrypt)
  print("\n")
  
  #SHA1 HASH TEST
  print("SHA1 Hash")
  sha1_1 = Crypto_sha1("ucsd")
  sha1_msg_encrypt = sha1_1.sha1_encrypt()
  print("Sha1 Msg:", sha1_1.get_msg())
  print("Sha1 Encrypted Msg:", sha1_msg_encrypt)

  
main()


#Notes from: https://analyticsindiamag.com/implementing-encryption-and-decryption-of-data-in-python/

