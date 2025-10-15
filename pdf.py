#!/usr/bin/env python3
import argparse
import pikepdf
import sys

def encrypt_pdf(input_file, output_file, password):
    pdf = pikepdf.open(input_file)
    pdf.save(output_file, encryption=pikepdf.Encryption(owner=password, user=password, R=4))
    print(f"[+] Encrypted {output_file} with password.")

def decrypt_pdf(input_file, output_file, password):
    try:
        pdf = pikepdf.open(input_file, password=password)
        pdf.save(output_file)
        print(f"[+] Decrypted {output_file}")
    except pikepdf._qpdf.PasswordError:
        print("[-] Incorrect password!")

def check_pdf(input_file):
    try:
        pdf = pikepdf.open(input_file)
        print(f"[{'!' if pdf.is_encrypted else '+'}] {input_file} encrypted = {pdf.is_encrypted}")
    except Exception as e:
        print(f"Error reading PDF: {e}")

def cli():
    parser = argparse.ArgumentParser(description="PDF Protection Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", help="Encrypt PDF file")
    group.add_argument("-d", "--decrypt", help="Decrypt PDF file")
    group.add_argument("-c", "--check", help="Check PDF protection status")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-p", "--password", help="Password (required for encrypt/decrypt)")
    args = parser.parse_args()
    return args

def menu():
    print("==== PDF Protection Tool ====")
    print("1. Encrypt PDF")
    print("2. Decrypt PDF")
    print("3. Check PDF status")
    choice = input("Choose option (1-3): ")

    if choice == "1":
        infile = input("Enter input PDF: ")
        outfile = input("Enter output PDF: ")
        passwd = input("Enter password: ")
        encrypt_pdf(infile, outfile, passwd)

    elif choice == "2":
        infile = input("Enter input PDF: ")
        outfile = input("Enter output PDF: ")
        passwd = input("Enter password: ")
        decrypt_pdf(infile, outfile, passwd)

    elif choice == "3":
        infile = input("Enter input PDF: ")
        check_pdf(infile)

    else:
        print("Invalid choice!")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        args = cli()
        if args.encrypt:
            if not args.output or not args.password:
                print("[-] For encrypt, --output and --password are required.")
                sys.exit(1)
            encrypt_pdf(args.encrypt, args.output, args.password)
        elif args.decrypt:
            if not args.output or not args.password:
                print("[-] For decrypt, --output and --password are required.")
                sys.exit(1)
            decrypt_pdf(args.decrypt, args.output, args.password)
        elif args.check:
            check_pdf(args.check)
    else:
        menu()
