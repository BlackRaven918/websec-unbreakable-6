"""Generate secure keys: python app/key-generator.py 10 --with-hmac --output keys.json."""

import argparse
import json
import secrets
import string


def generate_key(length=80):
    groups = (string.ascii_uppercase, string.ascii_lowercase, string.digits)
    alphabet = "".join(groups) + "_"
    while True:
        key = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(char in group for char in key) for group in groups):
            return key


def main():
    parser = argparse.ArgumentParser(description="Generate secure keys (80 characters by default).")
    parser.add_argument("amount", type=int, help="number of keys to generate")
    parser.add_argument("--length", type=int, default=80, help="characters per key (minimum/default: 80)")
    parser.add_argument("-o", "--output", default="keys.json", help="output JSON file (default: keys.json)")
    parser.add_argument("--with-hmac", action="store_true", help="generate an independent mod63/HMAC key pair per message")
    args = parser.parse_args()
    if args.amount < 1:
        parser.error("amount must be a positive integer")
    if args.length < 80:
        parser.error("length must be at least 80")

    try:
        with open(args.output, "x", encoding="utf-8") as output:
            keys = []
            for _ in range(args.amount):
                encryption_key = generate_key(args.length)
                if args.with_hmac:
                    hmac_key = generate_key(80)
                    while hmac_key == encryption_key:
                        hmac_key = generate_key(80)
                    keys.append({"encryptionKey": encryption_key, "hmacKey": hmac_key})
                else:
                    keys.append(encryption_key)
            json.dump({"keys": keys}, output, indent=2)
            output.write("\n")
    except OSError as error:
        parser.exit(1, f"Could not write {args.output}: {error}\n")


if __name__ == "__main__":
    main()
