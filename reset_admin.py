"""Bezbedno resetovanje jedinog lokalnog admin naloga; ne briše prijave."""
import os, sqlite3, hashlib, secrets, sys, shutil
from pathlib import Path
from datetime import datetime
ROOT=Path(__file__).resolve().parent
DATABASE=Path(os.environ.get('DATABASE_PATH',str(Path(os.environ.get('DATA_DIR',str(ROOT)))/'data.sqlite3')))
name=os.environ.get('ADMIN_USERNAME','').strip()
password=os.environ.get('ADMIN_PASSWORD','')
if not name or not password:
    sys.exit('GRESKA: U istom CMD prozoru postavi ADMIN_USERNAME i ADMIN_PASSWORD pre komande python reset_admin.py')
if len(password)<12:
    sys.exit('GRESKA: Lozinka mora imati najmanje 12 znakova.')
if not DATABASE.is_file():
    sys.exit('GRESKA: Baza nije pronadjena: '+str(DATABASE)+'. Prvo pokreni python app.py za novu instalaciju.')
con=sqlite3.connect(str(DATABASE)); con.row_factory=sqlite3.Row
try:
    if not con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admins'").fetchone():
        sys.exit('GRESKA: Ne postoji tabela administratorskih naloga. Pokreni python app.py.')
    admins=con.execute('SELECT id, username FROM admins ORDER BY id').fetchall()
    if len(admins)>1:
        sys.exit('GRESKA: Postoji vise administratora. Alat namerno ne bira jednog automatski. Podrska je potrebna.')
    # Backup kreiran SQLite backup API-jem cak i uz WAL bazu.
    backup=DATABASE.with_name(DATABASE.stem+'.backup-admin-'+datetime.now().strftime('%Y%m%d-%H%M%S')+'.sqlite3')
    with sqlite3.connect(str(backup)) as dest: con.backup(dest)
    salt=secrets.token_hex(16)
    digest=hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),salt.encode('ascii'),1_000_000).hex()
    pass_hash='pbkdf2:sha256:1000000$'+salt+'$'+digest
    if admins:
        con.execute('UPDATE admins SET username=?,password_hash=? WHERE id=?',(name,pass_hash,admins[0]['id']))
    else:
        con.execute('INSERT INTO admins(username,password_hash) VALUES (?,?)',(name,pass_hash))
    con.commit()
    print('USPESNO: admin korisnicko ime i lozinka su podeseni.')
    print('Rezervna kopija baze:',backup)
    print('Sada pokreni: python app.py')
except sqlite3.Error as exc:
    con.rollback(); sys.exit('GRESKA u bazi: '+str(exc))
finally:
    con.close()
