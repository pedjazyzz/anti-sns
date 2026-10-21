import os, re, sqlite3, secrets, time, io, hashlib, csv, shutil, json
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, g, send_file, Response
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageOps, UnidentifiedImageError

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('DATA_DIR', BASE)
os.makedirs(DATA_DIR, exist_ok=True)
DB = os.environ.get('DATABASE_PATH', os.path.join(DATA_DIR, 'data.sqlite3'))
UPLOADS = os.environ.get('UPLOAD_FOLDER', os.path.join(DATA_DIR, 'uploads'))
os.makedirs(UPLOADS, exist_ok=True)
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
if os.environ.get('RENDER') == 'true' and (not app.secret_key or len(app.secret_key) < 32):
    raise RuntimeError('Render: postavi SECRET_KEY (najmanje 32 karaktera) u Environment podešavanjima.')
if not app.secret_key:
    app.secret_key = secrets.token_hex(32)
# In production set SECRET_KEY permanently; otherwise sessions expire on restart.
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '1' if os.environ.get('RENDER')=='true' else '0')=='1', MAX_CONTENT_LENGTH=16*1024*1024)

def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA busy_timeout=10000')
        g.db.execute('PRAGMA journal_mode=WAL')
    return g.db

@app.teardown_appcontext
def teardown(exc):
    conn=g.pop('db',None)
    if conn: conn.close()

def init_db():
    with app.app_context():
        db().executescript('''CREATE TABLE IF NOT EXISTS reports(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          platform TEXT NOT NULL CHECK(platform IN ('Facebook','Instagram')),
          profile_url TEXT NOT NULL UNIQUE,
          reason TEXT NOT NULL CHECK(reason IN ('Imitiranje identiteta','Lažno predstavljanje','Spam ili automatizacija','Koordinisano neautentično ponašanje','Drugo')),
          details TEXT NOT NULL,
          evidence_url TEXT,
          status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
          submitted_at TEXT NOT NULL, reviewed_at TEXT,
          review_note TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS throttle(id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS ix_reports_status ON reports(status, submitted_at);
        CREATE INDEX IF NOT EXISTS ix_throttle ON throttle(fingerprint, created_at);
        ''')
        cols={r['name'] for r in db().execute('PRAGMA table_info(reports)')}
        if 'image_name' not in cols: db().execute('ALTER TABLE reports ADD COLUMN image_name TEXT')
        if 'display_name' not in cols: db().execute('ALTER TABLE reports ADD COLUMN display_name TEXT')
        if 'avatar_name' not in cols: db().execute('ALTER TABLE reports ADD COLUMN avatar_name TEXT')
        if 'evidence_reviewed' not in cols: db().execute('ALTER TABLE reports ADD COLUMN evidence_reviewed INTEGER DEFAULT 0')
        db().executescript('''CREATE TABLE IF NOT EXISTS attachments(id INTEGER PRIMARY KEY,report_id INTEGER NOT NULL REFERENCES reports(id),file_name TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS appeals(id INTEGER PRIMARY KEY, report_id INTEGER NOT NULL, explanation TEXT NOT NULL, contact TEXT, created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending');
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, report_id INTEGER, action TEXT NOT NULL, created_at TEXT NOT NULL);''')
        db().commit()
        username=os.environ.get('ADMIN_USERNAME')
        password=os.environ.get('ADMIN_PASSWORD')
        if username and password and not db().execute('SELECT 1 FROM admins LIMIT 1').fetchone():
            db().execute('INSERT INTO admins(username,password_hash) VALUES (?,?)',(username,generate_password_hash(password)))
            db().commit()

init_db()

@app.before_request
def csrf_prepare():
    if '_csrf' not in session: session['_csrf']=secrets.token_urlsafe(32)
    if request.method=='POST':
        if request.form.get('website',''): abort(400)
        if not secrets.compare_digest(str(session.get('_csrf','')),str(request.form.get('_csrf',''))): abort(400,'Neispravan bezbednosni token.')

@app.context_processor
def context(): return {'csrf_token':session.get('_csrf'), 'year':datetime.now().year, 'logged_in': bool(session.get('admin_id'))}

def normalize_profile(value):
    value=value.strip().strip('<>')
    if not value: return None
    # Support copied Instagram handles in addition to direct profile addresses.
    if re.fullmatch(r'@[A-Za-z0-9._]{1,30}', value):
        value='instagram.com/'+value[1:]
    if value.startswith('//'): value='https:'+value
    if not re.match(r'^https?://', value, re.I):
        if '://' in value: return None
        value='https://'+value
    parsed=urlparse(value)
    try:
        valid_port = parsed.port in (None,80,443)
    except ValueError:
        return None
    if parsed.scheme.lower() not in ('http','https') or parsed.username or parsed.password or not valid_port: return None
    host=(parsed.hostname or '').lower()
    if host in ('facebook.com','www.facebook.com','m.facebook.com','web.facebook.com'):
        platform='Facebook'; host='www.facebook.com'
    elif host in ('instagram.com','www.instagram.com'):
        platform='Instagram'; host='www.instagram.com'
    else: return None
    path=re.sub('/+','/',parsed.path).rstrip('/')
    if not path or len(path)>180 or re.search(r'[^a-zA-Z0-9_./-]',path): return None
    if platform=='Instagram':
        # Accept only public profile URL, not post/reel/story links.
        name=path.strip('/')
        if '/' in name or name.lower() in ('p','reel','reels','stories','explore','accounts','direct'): return None
        if not re.fullmatch(r'[A-Za-z0-9._]{1,30}', name): return None
    else:
        disallowed=('posts','reel','watch','groups','events','marketplace','share','photo','story.php','permalink.php')
        if path.strip('/').lower().split('/')[0] in disallowed: return None
        if path.lower()=='/profile.php':
            from urllib.parse import parse_qs
            identity=parse_qs(parsed.query).get('id',[''])[0]
            if not re.fullmatch(r'\d{3,24}',identity): return None
            return platform,'https://www.facebook.com/profile.php?id='+identity
    return platform, 'https://'+host+path

def valid_evidence(value):
    if not value: return True
    if len(value)>450: return False
    if not re.match(r'^https?://',value,re.I):
        if '://' in value: return False
        value='https://'+value
    p=urlparse(value)
    try:
        valid_port = p.port in (None,80,443)
    except ValueError:
        return False
    return p.scheme.lower() in ('http','https') and bool(p.hostname) and '.' in p.hostname and not p.username and not p.password and valid_port

@app.route('/')
def home():
    approved=db().execute("SELECT COUNT(*) n FROM reports WHERE status='approved'").fetchone()['n']
    pending=db().execute("SELECT COUNT(*) n FROM reports WHERE status='pending'").fetchone()['n']
    rejected=db().execute("SELECT COUNT(*) n FROM reports WHERE status='rejected'").fetchone()['n']
    total=approved+pending+rejected
    recent=db().execute("SELECT * FROM reports WHERE status='approved' ORDER BY reviewed_at DESC LIMIT 5").fetchall()
    return render_template('home.html',approved=approved,pending=pending,rejected=rejected,total=total,recent=recent)

@app.route('/baza')
def directory():
    platform=request.args.get('platform','')
    if platform not in ('Facebook','Instagram'): platform=''
    q=request.args.get('q','').strip()[:100]
    sql="SELECT * FROM reports WHERE status='approved'"; args=[]
    if platform: sql+=' AND platform=?'; args.append(platform)
    if q: sql+=' AND (profile_url LIKE ? OR reason LIKE ? OR display_name LIKE ?)'; args.extend(['%'+q+'%','%'+q+'%','%'+q+'%'])
    sql+=' ORDER BY reviewed_at DESC LIMIT 200'
    rows=db().execute(sql,args).fetchall()
    reason=request.args.get('reason','')
    # Additional filters happen on result set; public only, as above.
    if reason: rows=[r for r in rows if r['reason']==reason]
    return render_template('directory.html',reports=rows,q=q,platform=platform,reason=reason)

@app.route('/prijavi',methods=['GET','POST'])
def submit():
    if request.method=='POST':
        raw_profiles=request.form.get('profile_urls','').strip() or request.form.get('profile_url','').strip()
        profile_lines=[x.strip() for x in raw_profiles.splitlines() if x.strip()]
        reason=request.form.get('reason','')
        details=request.form.get('details','').strip()
        evidence=request.form.get('evidence_url','').strip()
        screenshots=request.files.getlist('screenshots') or request.files.getlist('screenshot')
        screenshots=[f for f in screenshots if f and f.filename]
        parsed_list=[normalize_profile(x) for x in profile_lines]
        if not profile_lines:
            flash('Unesi bar jedan link profila ili Instagram @korisnicko_ime. Opis može ostati prazan.','error')
            return render_template('submit.html',values=request.form),400
        if len(profile_lines)>10:
            flash('Možeš poslati najviše 10 profila odjednom. Za više profila pošalji novu prijavu.','error')
            return render_template('submit.html',values=request.form),400
        for i, (original, normalized) in enumerate(zip(profile_lines, parsed_list),start=1):
            if normalized is None:
                flash(f'Link u redu {i} nije prepoznat kao direktan Facebook ili Instagram PROFIL: {original[:90]}. Ako je link do objave ili deljenja, otvori nalog i kopiraj adresu profila.','error')
                return render_template('submit.html',values=request.form),400
        if len(set(x[1] for x in parsed_list))!=len(parsed_list):
            flash('Isti profil je unet više puta. Svaki nalog unesi samo jednom.','error')
            return render_template('submit.html',values=request.form),400
        parsed=parsed_list[0]
        allowed=('Imitiranje identiteta','Lažno predstavljanje','Spam ili automatizacija','Koordinisano neautentično ponašanje','Drugo')
        if not parsed or reason not in allowed or len(details)>1500 or not valid_evidence(evidence):
            flash('Proveri link profila, razlog, opis (opciono, najviše 1500 znakova) i link dokaza.','error')
            return render_template('submit.html',values=request.form),400
        if len(screenshots)>3:
            flash('Dozvoljene su najviše tri slike po prijavi.','error'); return render_template('submit.html',values=request.form),400
        images=[]
        for screenshot in screenshots:
            try:
                if len(screenshot.read(5*1024*1024+1))>5*1024*1024: raise ValueError('Size')
                screenshot.stream.seek(0)
                image=Image.open(screenshot.stream)
                if image.format not in ('PNG','JPEG','WEBP'): raise ValueError('Format')
                image=ImageOps.exif_transpose(image); image.thumbnail((1600,1600)); image=image.convert('RGB')
                output=io.BytesIO(); image.save(output,format='JPEG',quality=82,optimize=True)
                images.append(output.getvalue())
            except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
                flash('Slike moraju biti JPG, PNG ili WEBP, svaka do 5 MB.','error')
                return render_template('submit.html',values=request.form),400
        # Lightweight rate limit. Reverse-proxy IP configuration needed when behind a trusted proxy.
        fingerprint=hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()
        now=int(time.time())
        conn=db(); conn.execute('DELETE FROM throttle WHERE created_at < ?',(now-3600,))
        recent=conn.execute('SELECT COUNT(*) n FROM throttle WHERE fingerprint=? AND created_at>?',(fingerprint,now-3600)).fetchone()['n']
        if recent>=5:
            conn.commit(); flash('Previše prijava sa ove veze. Pokušaj ponovo kasnije.','error'); return redirect(url_for('submit'))
        saved=[]; inserted=0
        try:
            for platform, profile_url in parsed_list:
                if conn.execute('SELECT id FROM reports WHERE profile_url=?',(profile_url,)).fetchone(): continue
                cur=conn.execute('INSERT INTO reports(platform,profile_url,reason,details,evidence_url,submitted_at,image_name) VALUES(?,?,?,?,?,?,NULL)',(platform,profile_url,reason,details or 'Opis nije dostavljen.',evidence,datetime.now(timezone.utc).isoformat()))
                for img in images:
                    name=secrets.token_hex(18)+'.jpg'
                    with open(os.path.join(UPLOADS,name),'wb') as f: f.write(img)
                    saved.append(name)
                    conn.execute('INSERT INTO attachments(report_id,file_name) VALUES(?,?)',(cur.lastrowid,name))
                inserted+=1
            if inserted:
                conn.execute('INSERT INTO throttle(fingerprint,created_at) VALUES(?,?)',(fingerprint,now))
            conn.commit()
        except Exception:
            conn.rollback()
            for name in saved:
                try: os.unlink(os.path.join(UPLOADS,name))
                except OSError: pass
            raise
        if not inserted:
            flash('Svi ovi profili su već evidentirani.','info'); return redirect(url_for('submit'))
        flash('Prijava je primljena i čeka moderatorsku proveru. Hvala!','success')
        return redirect(url_for('submit'))
    return render_template('submit.html', values={})

def admin_only(fn):
    @wraps(fn)
    def wrapped(*args,**kwargs):
        if not session.get('admin_id') or not db().execute('SELECT 1 FROM admins WHERE id=?',(session['admin_id'],)).fetchone():
            session.clear()
            return redirect(url_for('login'))
        return fn(*args,**kwargs)
    return wrapped

@app.route('/admin/prijava',methods=['GET','POST'])
def login():
    if request.method=='POST':
        user=request.form.get('username',''); password=request.form.get('password','')
        row=db().execute('SELECT * FROM admins WHERE username=?',(user,)).fetchone()
        fingerprint=hashlib.sha256(('login:'+(request.remote_addr or 'unknown')).encode()).hexdigest()
        now=int(time.time())
        attempts=db().execute('SELECT COUNT(*) n FROM throttle WHERE fingerprint=? AND created_at>?',(fingerprint,now-900)).fetchone()['n']
        if attempts>=10: abort(429,'Previše pokušaja. Pokušaj za 15 minuta.')
        if row and check_password_hash(row['password_hash'],password):
            session.clear(); session['admin_id']=row['id']; session['_csrf']=secrets.token_urlsafe(32)
            return redirect(url_for('admin'))
        db().execute('INSERT INTO throttle(fingerprint,created_at) VALUES(?,?)',(fingerprint,now));db().commit()
        flash('Neispravno korisničko ime ili lozinka.','error')
    return render_template('login.html')

@app.route('/admin/odjava',methods=['POST'])
@admin_only
def logout():
    session.clear(); return redirect(url_for('home'))

@app.route('/admin')
@admin_only
def admin():
    status=request.args.get('status','pending')
    if status not in ('pending','approved','rejected'): status='pending'
    rows=db().execute('SELECT * FROM reports WHERE status=? ORDER BY submitted_at DESC LIMIT 300',(status,)).fetchall()
    counts={s:db().execute('SELECT COUNT(*) n FROM reports WHERE status=?',(s,)).fetchone()['n'] for s in ('pending','approved','rejected')}
    attachments={r['id']:db().execute('SELECT * FROM attachments WHERE report_id=?',(r['id'],)).fetchall() for r in rows}
    new_appeals=db().execute("SELECT COUNT(*) n FROM appeals WHERE status='pending'").fetchone()['n']
    recent_actions=db().execute('SELECT a.*,r.profile_url FROM audit_log a LEFT JOIN reports r ON a.report_id=r.id ORDER BY a.id DESC LIMIT 8').fetchall()
    return render_template('admin.html',reports=rows,status=status,counts=counts,attachments=attachments,new_appeals=new_appeals,recent_actions=recent_actions)

def profile_label(report):
    """Fall back to public URL handle, never claim it is a real person's name."""
    if report['display_name']:
        return report['display_name']
    parsed=urlparse(report['profile_url'])
    if parsed.path=='/profile.php':
        from urllib.parse import parse_qs
        return 'Facebook nalog '+parse_qs(parsed.query).get('id',[''])[0]
    return '@'+parsed.path.strip('/').split('/')[0]

app.jinja_env.globals['profile_label']=profile_label

@app.route('/avatar/<int:report_id>')
def avatar_image(report_id):
    r=db().execute('SELECT status,avatar_name FROM reports WHERE id=?',(report_id,)).fetchone()
    if not r or not r['avatar_name'] or (r['status']!='approved' and not session.get('admin_id')):abort(404)
    return send_file(os.path.join(UPLOADS,r['avatar_name']),mimetype='image/jpeg',max_age=0)

@app.route('/admin/identitet/<int:report_id>',methods=['POST'])
@admin_only
def edit_identity(report_id):
    r=db().execute('SELECT * FROM reports WHERE id=?',(report_id,)).fetchone()
    if not r:abort(404)
    name=request.form.get('display_name','').strip()
    if len(name)>100 or any(ord(c)<32 for c in name): abort(400,'Naziv je predugačak ili neispravan')
    avatar=request.files.get('avatar')
    new_avatar=None
    if avatar and avatar.filename:
        try:
            if len(avatar.read(3*1024*1024+1))>3*1024*1024: raise ValueError('Prevelika slika')
            avatar.stream.seek(0)
            im=Image.open(avatar.stream)
            if im.format not in ('JPEG','PNG','WEBP'):raise ValueError('Nepodržan format')
            im=ImageOps.exif_transpose(im); im.thumbnail((360,360)); im=im.convert('RGB')
            output=io.BytesIO(); im.save(output,format='JPEG',quality=84)
            new_avatar=secrets.token_hex(16)+'.jpg'
            with open(os.path.join(UPLOADS,new_avatar),'wb') as f:f.write(output.getvalue())
        except (OSError,UnidentifiedImageError,ValueError,Image.DecompressionBombError):
            flash('Slika mora biti JPEG/PNG/WEBP do 3 MB.','error');return redirect(url_for('admin',status=r['status']))
    try:
        db().execute('UPDATE reports SET display_name=?,avatar_name=COALESCE(?,avatar_name) WHERE id=?',(name,new_avatar,report_id))
        db().execute('INSERT INTO audit_log(report_id,action,created_at) VALUES(?,?,?)',(report_id,'identity_updated',datetime.now(timezone.utc).isoformat()))
        db().commit()
    except Exception:
        if new_avatar:
            try:os.remove(os.path.join(UPLOADS,new_avatar))
            except OSError:pass
        raise
    flash('Podaci za karticu su sačuvani.','success')
    return redirect(url_for('admin',status=r['status']))

@app.route('/admin/odluka/<int:report_id>',methods=['POST'])
@admin_only
def decision(report_id):
    action=request.form.get('action')
    if action not in ('approved','rejected','pending'): abort(400)
    note=request.form.get('review_note','').strip()[:500]
    preset=request.form.get('decision_preset','').strip()
    approved_presets={
        'evidence':'Pregledani su priloženi dokazi; prijava je odobrena za javni prikaz. To nije potvrda platforme.',
        'public':'Provereni su dostavljeni javni linkovi i sadržaj; prijava je odobrena za javni prikaz.',
        'limited':'Prijava je pregledana i objavljena uz napomenu o ograničenosti dostupnih informacija.'
    }
    rejected_presets={
        'insufficient':'Nema dovoljno proverljivih dokaza za objavljivanje.',
        'duplicate':'Duplirana ili već evidentirana prijava.',
        'invalid':'Nalog ili navodi ne odgovaraju pravilima sajta.'
    }
    if not note:
        options=approved_presets if action=='approved' else rejected_presets if action=='rejected' else {}
        note=options.get(preset,'')
    if action=='approved' and not note:
        flash('Izaberi gotov razlog odluke ili napiši kratku belešku pre objavljivanja.','error')
        return redirect(url_for('admin',status='pending'))
    # Dokaz je opcioni. Moderatorsko odobrenje označava samo pregled prijave,
    # nikako potvrdu da je nalog lažan ili da je izvršeno kršenje pravila.
    cursor=db().execute('UPDATE reports SET status=?, reviewed_at=?, review_note=? WHERE id=?',(action,datetime.now(timezone.utc).isoformat(),note,report_id))
    db().execute('INSERT INTO audit_log(report_id,action,created_at) VALUES(?,?,?)',(report_id,action,datetime.now(timezone.utc).isoformat()))
    db().commit()
    if cursor.rowcount==0: abort(404)
    flash('Odluka je sačuvana.','success'); return redirect(url_for('admin'))


@app.route('/profil/<int:report_id>')
def profile(report_id):
    r=db().execute('SELECT * FROM reports WHERE id=? AND status="approved"',(report_id,)).fetchone()
    if not r: abort(404)
    attachments=db().execute('SELECT * FROM attachments WHERE report_id=?',(report_id,)).fetchall()
    return render_template('profile.html',r=r,attachments=attachments)

@app.route('/dokaz/<int:report_id>')
def evidence_image(report_id):
    r=db().execute('SELECT status,image_name FROM reports WHERE id=?',(report_id,)).fetchone()
    if not r or not r['image_name']: abort(404)
    if r['status']!='approved' and not session.get('admin_id'): abort(404)
    return send_file(os.path.join(UPLOADS, r['image_name']),mimetype='image/jpeg',max_age=0)

@app.route('/dokaz/prilog/<int:attachment_id>')
def attachment_image(attachment_id):
    r=db().execute('SELECT a.file_name,r.status FROM attachments a JOIN reports r ON a.report_id=r.id WHERE a.id=?',(attachment_id,)).fetchone()
    if not r or (r['status']!='approved' and not session.get('admin_id')): abort(404)
    return send_file(os.path.join(UPLOADS,r['file_name']),mimetype='image/jpeg',max_age=0)

@app.route('/admin/izvoz.csv')
@admin_only
def export_csv():
    stream=io.StringIO(); writer=csv.writer(stream)
    writer.writerow(['id','platforma','url','razlog','status','datum','datum_provere'])
    for r in db().execute('SELECT id,platform,profile_url,reason,status,submitted_at,reviewed_at FROM reports ORDER BY id'):
        writer.writerow([("'"+str(x) if str(x).startswith(('=','+','-','@')) else x) if x is not None else '' for x in r])
    return Response('﻿'+stream.getvalue(),mimetype='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename=provera-profili.csv'})

@app.route('/statistika.csv')
def public_csv():
    stream=io.StringIO(); writer=csv.writer(stream); writer.writerow(['datum','platforma','broj_odobrenih'])
    for r in db().execute("SELECT substr(reviewed_at,1,10) day, platform, COUNT(*) n FROM reports WHERE status='approved' GROUP BY day,platform ORDER BY day"):
        writer.writerow([r['day'],r['platform'],r['n']])
    return Response('﻿'+stream.getvalue(),mimetype='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename=statistika.csv'})

@app.route('/zalba/<int:report_id>',methods=['GET','POST'])
def appeal(report_id):
    r=db().execute("SELECT * FROM reports WHERE id=? AND status='approved'",(report_id,)).fetchone()
    if not r: abort(404)
    if request.method=='POST':
        explanation=request.form.get('explanation','').strip(); contact=request.form.get('contact','').strip()
        if not 30<=len(explanation)<=2000 or len(contact)>160:
            flash('Unesi obrazloženje od 30 do 2000 znakova.','error'); return render_template('appeal.html',r=r),400
        fingerprint=hashlib.sha256(('appeal:'+(request.remote_addr or 'unknown')).encode()).hexdigest(); now=int(time.time())
        if db().execute('SELECT COUNT(*) n FROM throttle WHERE fingerprint=? AND created_at>?',(fingerprint,now-3600)).fetchone()['n']>=3: abort(429)
        db().execute('INSERT INTO appeals(report_id,explanation,contact,created_at) VALUES(?,?,?,?)',(report_id,explanation,contact,datetime.now(timezone.utc).isoformat()))
        db().execute('INSERT INTO throttle(fingerprint,created_at) VALUES(?,?)',(fingerprint,now)); db().commit()
        flash('Zahtev je primljen na proveru.','success');return redirect(url_for('profile',report_id=report_id))
    return render_template('appeal.html',r=r)

@app.route('/admin/zalbe')
@admin_only
def admin_appeals():
    rows=db().execute('SELECT a.*,r.profile_url FROM appeals a JOIN reports r ON a.report_id=r.id ORDER BY a.created_at DESC LIMIT 200').fetchall()
    return render_template('appeals.html',rows=rows)

@app.route('/admin/zalba/<int:appeal_id>',methods=['POST'])
@admin_only
def resolve_appeal(appeal_id):
    action=request.form.get('action')
    if action not in ('resolved','rejected'):abort(400)
    db().execute('UPDATE appeals SET status=? WHERE id=?',(action,appeal_id)); db().commit()
    flash('Zahtev je obrađen.','success');return redirect(url_for('admin_appeals'))

@app.route('/statistika')
def statistics():
    conn=db()
    total=conn.execute('SELECT COUNT(*) n FROM reports').fetchone()['n']
    statuses={name:conn.execute('SELECT COUNT(*) n FROM reports WHERE status=?',(name,)).fetchone()['n'] for name in ('approved','pending','rejected')}
    platforms=[dict(r) for r in conn.execute('SELECT platform,COUNT(*) n FROM reports WHERE status="approved" GROUP BY platform')]
    reasons=[dict(r) for r in conn.execute('SELECT reason, COUNT(*) n FROM reports WHERE status="approved" GROUP BY reason ORDER BY n DESC')]
    trend=[dict(r) for r in conn.execute("SELECT substr(reviewed_at,1,10) day, COUNT(*) n FROM reports WHERE status='approved' AND reviewed_at IS NOT NULL GROUP BY day ORDER BY day DESC LIMIT 14")][::-1]
    return render_template('statistics.html',total=total,statuses=statuses,platforms=platforms,reasons=reasons,trend=trend)

@app.route('/pravila')
def rules(): return render_template('rules.html')

@app.route('/zahtev-za-ispravku',methods=['GET','POST'])
def correction():
    # Contact via site owner's configured public address; never expose personal data from reports.
    return render_template('correction.html',contact_email=os.environ.get('CONTACT_EMAIL',''))

@app.errorhandler(404)
def not_found(e): return render_template('error.html',message='Stranica nije pronađena.'),404

@app.after_request
def security_headers(response):
    response.headers['Cache-Control']='no-store' if request.path.startswith('/admin') else 'private, max-age=0'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='strict-origin-when-cross-origin'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    return response

if __name__=='__main__':
    app.run(host='127.0.0.1',port=int(os.environ.get('PORT','5000')),debug=False)
