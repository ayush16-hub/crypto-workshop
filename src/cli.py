"""Command-line interface for the two-folder workshop demonstration."""
import argparse, getpass, shutil, sys
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from .key_manager import generate_keypair, load_private, load_public
from .sender import create_package
from .receiver import decrypt_package, verify_package, ExchangeError

ROOT = Path(__file__).resolve().parents[1]
def password(prompt):
    a = getpass.getpass(prompt); b = getpass.getpass("Confirm password: ") if "new" in prompt.lower() else a
    if a != b: raise ValueError("Passwords did not match")
    if len(a) < 12: raise ValueError("Use a password of at least 12 characters")
    return a.encode()
def main(argv=None):
    p=argparse.ArgumentParser(description="Secure examination-paper exchange workshop")
    sub=p.add_subparsers(dest="command",required=True)
    g=sub.add_parser("generate-keys"); g.add_argument("--base",type=Path,default=ROOT)
    e=sub.add_parser("encrypt"); e.add_argument("--input",type=Path,required=True); e.add_argument("--output",type=Path); e.add_argument("--base",type=Path,default=ROOT)
    v=sub.add_parser("verify"); v.add_argument("--package",type=Path,required=True); v.add_argument("--sender-public",type=Path); v.add_argument("--base",type=Path,default=ROOT)
    d=sub.add_parser("decrypt"); d.add_argument("--package",type=Path,required=True); d.add_argument("--output-dir",type=Path); d.add_argument("--base",type=Path,default=ROOT)
    args=p.parse_args(argv); base=args.base
    try:
        if args.command=="generate-keys":
            sp=base/"sender_folder/keys/sender_private.pem"; su=base/"sender_folder/keys/sender_public.pem"; rp=base/"recipient_folder/keys/recipient_private.pem"; ru=base/"recipient_folder/keys/recipient_public.pem"
            generate_keypair(sp,su,password("New sender private-key password: ")); generate_keypair(rp,ru,password("New recipient private-key password: "))
            trusted=base/"recipient_folder/trusted_keys"; trusted.mkdir(parents=True,exist_ok=True); shutil.copy2(su,trusted/"sender_public.pem")
            print("Keys generated; sender public key copied to recipient trusted_keys. Verify fingerprints out of band.")
        elif args.command=="encrypt":
            key=load_private(base/"sender_folder/keys/sender_private.pem",password("Sender private-key password: ")); recipient=load_public(base/"recipient_folder/keys/recipient_public.pem")
            out=args.output or base/"sender_folder/outbox"/(args.input.stem+".secpkg"); create_package(args.input,out,key,recipient); print(f"Encrypted package created: {out}")
        elif args.command=="verify":
            pub=load_public(args.sender_public or base/"recipient_folder/trusted_keys/sender_public.pem"); verify_package(args.package,pub); print("Signature valid; package has not been decrypted.")
        else:
            pub=load_public(base/"recipient_folder/trusted_keys/sender_public.pem"); key=load_private(base/"recipient_folder/keys/recipient_private.pem",password("Recipient private-key password: "))
            out=decrypt_package(args.package,args.output_dir or base/"recipient_folder/decrypted",pub,key); print(f"Verified and decrypted file: {out}")
        return 0
    except (OSError, ValueError, ExchangeError, InvalidSignature) as exc:
        print(f"Error: {exc}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
