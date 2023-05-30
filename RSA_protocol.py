from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

# Генерация ключей
keyA = RSA.generate(2048)
keyB = RSA.generate(2048)

# Аутентификация и обмен данными
def protocol():
    # Аутентификация сторон
    challengeA = os.urandom(32)
    signerA = pkcs1_15.new(keyA)
    signatureA = signerA.sign(SHA256.new(challengeA))

    # Аутентификация стороны B
    challengeB = os.urandom(32)
    signerB = pkcs1_15.new(keyB)
    signatureB = signerB.sign(SHA256.new(challengeB))

    # Верификация стороны A
    verifierA = pkcs1_15.new(keyB.publickey())
    try:
        verifierA.verify(SHA256.new(challengeB), signatureB)
        print("Аутентификация Боба прошла успешно :)")
    except:
        print("Аутентификация Боба провалена :(")

    # Верификация стороны B
    verifierB = pkcs1_15.new(keyA.publickey())
    try:
        verifierB.verify(SHA256.new(challengeA), signatureA)
        print("Аутентификация Алисы прошла успешно :)")
    except:
        print("Аутентификация Алисы провалена :(")

    # Обмен данными
    message_to_bob = "Hello, Bob!"
    message_to_alice = "Hi, Alice!"

    # Отправка сообщения Бобу
    cipherA = PKCS1_OAEP.new(keyB.publickey())
    encrypted_messageA = cipherA.encrypt(message_to_bob.encode())
    signerA = pkcs1_15.new(keyA)
    signatureA = signerA.sign(SHA256.new(message_to_bob.encode()))

    # Расшифровка сообщения Бобом
    cipherB = PKCS1_OAEP.new(keyB)
    received_message = cipherB.decrypt(encrypted_messageA).decode()
    verifierB = pkcs1_15.new(keyA.publickey())
    try:
        verifierB.verify(SHA256.new(received_message.encode()), signatureA)
        print("Полученное Бобом сообщение:", received_message)       
    except:
        print("Тревога!!!")

    # Отправка сообщения Алисе
    cipherB = PKCS1_OAEP.new(keyA.publickey())
    encrypted_messageB = cipherB.encrypt(message_to_alice.encode())
    signerB = pkcs1_15.new(keyB)
    signatureB = signerB.sign(SHA256.new(message_to_alice.encode()))

    # Расшифровка сообщения Алисой
    cipherA = PKCS1_OAEP.new(keyA)
    received_message = cipherA.decrypt(encrypted_messageB).decode()
    verifierA = pkcs1_15.new(keyB.publickey())
    try:
        verifierA.verify(SHA256.new(received_message.encode()), signatureB)
        print("Полученное Алисой сообщение:", received_message)
    except:
        print("Тревога!!!")

# Выполнение протокола
protocol()